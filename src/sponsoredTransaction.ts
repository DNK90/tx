import { RLP } from '@ethereumjs/rlp'
import {
  BIGINT_2,
  BIGINT_8,
  MAX_INTEGER,
  bigIntToHex,
  bigIntToUnpaddedBytes,
  bytesToBigInt,
  toBytes,
  validateNoLeadingZeroes,
} from '@ethereumjs/util'
import { keccak256 } from 'ethereum-cryptography/keccak.js'

import { BaseTransaction } from './baseTransaction.js'
import * as Legacy from './capabilities/legacy.js'
import { Capability, TransactionType} from './types.js'

import type {
  TxData as AllTypesTxData,
  TxValuesArray as AllTypesTxValuesArray,
  JsonTx,
  TxOptions,
} from './types.js'
import type { Common } from '@ethereumjs/common'
import * as EIP2718 from "./capabilities/eip2718";

type TxData = AllTypesTxData[TransactionType.Sponsored]
type TxValuesArray = AllTypesTxValuesArray[TransactionType.Sponsored]

function meetsEIP155(_v: bigint, chainId: bigint) {
  const v = Number(_v)
  const chainIdDoubled = Number(chainId) * 2
  return v === chainIdDoubled + 35 || v === chainIdDoubled + 36
}

/**
 * An Ethereum non-typed (legacy) transaction
 */
export class SponsoredTransaction extends BaseTransaction<TransactionType.Sponsored> {
  public readonly chainId: bigint
  public readonly maxPriorityFeePerGas: bigint
  public readonly maxFeePerGas: bigint
  public readonly gasPrice: bigint
  public readonly payerR: bigint
  public readonly payerS: bigint
  public readonly payerV: bigint
  public readonly expiredTime: bigint
  public readonly payerUrl!: string
  public readonly common: Common

  /**
   * Instantiate a transaction from a data dictionary.
   *
   * Format: { nonce, gasPrice, gasLimit, to, value, data, v, r, s }
   *
   * Notes:
   * - All parameters are optional and have some basic default values
   */
  public static fromTxData(txData: TxData, opts: TxOptions = {}) {
    return new SponsoredTransaction(txData, opts)
  }

  /**
   * Instantiate a transaction from the serialized tx.
   *
   * Format: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
   */
  public static fromSerializedTx(serialized: Uint8Array, opts: TxOptions = {}) {
    const values = RLP.decode(serialized)

    if (!Array.isArray(values)) {
      throw new Error('Invalid serialized tx input. Must be array')
    }

    return this.fromValuesArray(values as TxValuesArray, opts)
  }

  /**
   * Create a transaction from a values array.
   *
   * Format: `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`
   */
  public static fromValuesArray(values: TxValuesArray, opts: TxOptions = {}) {
    // If length is not 6, it has length 9. If v/r/s are empty Uint8Arrays, it is still an unsigned transaction
    // This happens if you get the RLP data from `raw()`
    if (values.length < 11 && values.length > 17) {
      throw new Error(
        'Invalid transaction. Only expecting 6 values (for unsigned tx) or 9 values (for signed tx).'
      )
    }

    const [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasPrice, gasLimit, to, value, data, v, r, s, payerV, payerR, payerS, expiredTime, payerUrl] = values
    this._validateNotArray({ chainId, v })
    validateNoLeadingZeroes({ chainId, nonce, gasPrice, gasLimit, payerV, payerR, payerS, expiredTime })

    return new SponsoredTransaction(
      {
        chainId: bytesToBigInt(chainId),
        nonce,
        maxPriorityFeePerGas,
        maxFeePerGas,
        gasPrice,
        gasLimit,
        to,
        value,
        data,
        v,
        r,
        s,
        payerV: payerV !== undefined ? bytesToBigInt(payerV) : undefined,
        payerR,
        payerS,
        expiredTime,
        payerUrl
      },
      opts
    )
  }

  /**
   * This constructor takes the values, validates them, assigns them and freezes the object.
   *
   * It is not recommended to use this constructor directly. Instead use
   * the static factory methods to assist in creating a Transaction object from
   * varying data types.
   */
  public constructor(txData: TxData, opts: TxOptions = {}) {
    super({ ...txData, type: TransactionType.Sponsored }, opts)

    const {
      chainId,
      nonce,
      maxPriorityFeePerGas,
      maxFeePerGas,
      gasPrice,
      gasLimit,
      to,
      value,
      data,
      v,
      r,
      s,
      payerV,
      payerR,
      payerS,
      expiredTime,
      payerUrl
  } = txData

    this.common = this._getCommon(opts.common, chainId)
    this.chainId = this.common.chainId()

    this.maxFeePerGas = bytesToBigInt(toBytes(maxFeePerGas === '' ? '0x' : maxFeePerGas))
    this.maxPriorityFeePerGas = bytesToBigInt(
      toBytes(maxPriorityFeePerGas === '' ? '0x' : maxPriorityFeePerGas)
    )
    this.gasPrice = bytesToBigInt(toBytes(gasPrice === '' ? '0x' : gasPrice))

    if (this.gasPrice * this.gasLimit > MAX_INTEGER) {
      const msg = this._errorMsg('gas limit * gasPrice cannot exceed MAX_INTEGER (2^256-1)')
      throw new Error(msg)
    }
    this._validateCannotExceedMaxInteger({ gasPrice: this.gasPrice })
    this.payerV = bytesToBigInt(toBytes(payerV))
    this.payerR = bytesToBigInt(toBytes(payerR))
    this.payerS = bytesToBigInt(toBytes(payerS))
    this.expiredTime = bytesToBigInt(toBytes(expiredTime))

    BaseTransaction._validateNotArray(txData)
    const freeze = opts?.freeze ?? true
    if (freeze) {
      Object.freeze(this)
    }
  }

  /**
   * Returns a Uint8Array Array of the raw Bytes of the sponsored transaction, in order.
   *
   * Format: `[chainId, nonce, gasPrice, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, v, r, s, payerV, payerR, payerS, expiredTime]`
   *
   * For an unsigned tx this method returns the empty Bytes values
   * for the signature parameters `v`, `r` and `s`. For an EIP-155 compliant
   * representation have a look at {@link Transaction.getMessageToSign}.
   */
  raw(): TxValuesArray {
    return [
      bigIntToUnpaddedBytes(this.chainId),
      bigIntToUnpaddedBytes(this.nonce),
      bigIntToUnpaddedBytes(this.maxPriorityFeePerGas),
      bigIntToUnpaddedBytes(this.maxFeePerGas),
      bigIntToUnpaddedBytes(this.gasPrice),
      bigIntToUnpaddedBytes(this.gasLimit),
      this.to !== undefined ? this.to.bytes : new Uint8Array(0),
      bigIntToUnpaddedBytes(this.value),
      this.data,
      bigIntToUnpaddedBytes(this.payerV),
      bigIntToUnpaddedBytes(this.payerR),
      bigIntToUnpaddedBytes(this.payerS),
      bigIntToUnpaddedBytes(this.expiredTime),
      this.v !== undefined ? bigIntToUnpaddedBytes(this.v) : new Uint8Array(0),
      this.r !== undefined ? bigIntToUnpaddedBytes(this.r) : new Uint8Array(0),
      this.s !== undefined ? bigIntToUnpaddedBytes(this.s) : new Uint8Array(0),
      this.payerUrl
    ]
  }

  /**
   * Returns the serialized encoding of the legacy transaction.
   *
   * Format: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
   *
   * For an unsigned tx this method uses the empty Uint8Array values for the
   * signature parameters `v`, `r` and `s` for encoding. For an EIP-155 compliant
   * representation for external signing use {@link Transaction.getMessageToSign}.
   */
  serialize(): Uint8Array {
    return RLP.encode(this.raw())
  }

  /**
   * Returns the raw unsigned tx, which can be used
   * to sign the transaction (e.g. for sending to a hardware wallet).
   *
   * Note: the raw message message format for the legacy tx is not RLP encoded
   * and you might need to do yourself with:
   *
   * ```javascript
   * import { RLP } from '@ethereumjs/rlp'
   * const message = tx.getMessageToSign()
   * const serializedMessage = RLP.encode(message)) // use this for the HW wallet input
   * ```
   */
  getMessageToSign(): Uint8Array {
    return EIP2718.serialize(this, this.raw().slice(0, 12))
  }

  /**
   * Returns the hashed serialized unsigned tx, which can be used
   * to sign the transaction (e.g. for sending to a hardware wallet).
   */
  getHashedMessageToSign() {
    const message = this.getMessageToSign()
    return keccak256(RLP.encode(message))
  }

  /**
   * The amount of gas paid for the data in this tx
   */
  getDataFee(): bigint {
    return Legacy.getDataFee(this)
  }

  /**
   * The up front amount that an account must have for this transaction to be valid
   */
  getUpfrontCost(): bigint {
    return this.gasLimit * this.gasPrice + this.value
  }

  /**
   * Computes a sha3-256 hash of the serialized tx.
   *
   * This method can only be used for signed txs (it throws otherwise).
   * Use {@link Transaction.getMessageToSign} to get a tx hash for the purpose of signing.
   */
  hash(): Uint8Array {
    return Legacy.hash(this)
  }

  /**
   * Computes a sha3-256 hash which can be used to verify the signature
   */
  getMessageToVerifySignature() {
    if (!this.isSigned()) {
      const msg = this._errorMsg('This transaction is not signed')
      throw new Error(msg)
    }
    return this.getHashedMessageToSign()
  }

  /**
   * Returns the public key of the sender
   */
  getSenderPublicKey(): Uint8Array {
    return Legacy.getSenderPublicKey(this)
  }

  /**
   * Process the v, r, s values from the `sign` method of the base transaction.
   */
  protected _processSignature(v: bigint, r: Uint8Array, s: Uint8Array) {
    if (this.supports(Capability.EIP155ReplayProtection)) {
      v += this.common.chainId() * BIGINT_2 + BIGINT_8
    }

    const opts = { ...this.txOptions, common: this.common }

    return SponsoredTransaction.fromTxData(
      {
        chainId: this.chainId,
        nonce: this.nonce,
        gasPrice: this.gasPrice,
        maxPriorityFeePerGas: this.maxPriorityFeePerGas,
        maxFeePerGas: this.maxFeePerGas,
        gasLimit: this.gasLimit,
        to: this.to,
        value: this.value,
        data: this.data,
        expiredTime: this.expiredTime,
        v,
        r: bytesToBigInt(r),
        s: bytesToBigInt(s),
        payerV: this.payerV,
        payerR: this.payerR,
        payerS: this.payerS
      },
      opts
    )
  }

  /**
   * Returns an object with the JSON representation of the transaction.
   */
  toJSON(): JsonTx {
    const baseJson = super.toJSON()
    return {
      ...baseJson,
      gasPrice: bigIntToHex(this.gasPrice),
      chainId: bigIntToHex(this.chainId),
      maxPriorityFeePerGas: bigIntToHex(this.maxPriorityFeePerGas),
      maxFeePerGas: bigIntToHex(this.maxFeePerGas),
      payerV: this.payerV !== undefined ? bigIntToHex(this.payerV) : undefined,
      payerR: this.payerR !== undefined ? bigIntToHex(this.payerR) : undefined,
      payerS: this.payerS !== undefined ? bigIntToHex(this.payerS) : undefined,
      expiredTime: bigIntToHex(this.expiredTime),
      payerUrl: this.payerUrl
    }
  }

  /**
   * Return a compact error string representation of the object
   */
  public errorStr() {
    let errorStr = this._getSharedErrorPostfix()
    errorStr += ` gasPrice=${this.gasPrice} maxFeePerGas=${this.maxFeePerGas} maxPriorityFeePerGas=${this.maxPriorityFeePerGas} expiredTime=${this.expiredTime}`
    return errorStr
  }

  /**
   * Internal helper function to create an annotated error message
   *
   * @param msg Base error message
   * @hidden
   */
  protected _errorMsg(msg: string) {
    return Legacy.errorMsg(this, msg)
  }
}
