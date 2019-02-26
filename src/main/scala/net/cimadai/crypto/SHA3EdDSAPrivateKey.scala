package net.cimadai.crypto

import java.util

import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec

/**
  * Copyright Daisuke SHIMADA, Richard Gomes -  All Rights Reserved.
  * https://github.com/cimadai/iroha-scala
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *      http://www.apache.org/licenses/LICENSE-2.0
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */



trait SHA3EdDSAPrivateKey {
  import net.i2p.crypto.eddsa.EdDSAPrivateKey
  import net.i2p.crypto.eddsa.math.GroupElement
  private[crypto] val self: EdDSAPrivateKey
  val seed: Array[Byte]
  val h: Array[Byte]
  val a: Array[Byte]
  val A: GroupElement
  /** Return the public key as a byte array. */
  def toPublicKeyBytes: Array[Byte]
  /** Return the public key as an hexadecimal [String]. */
  def toPublicKeyHex: String
  /** Return the private key as a byte array. */
  def toPrivateKeyBytes: Array[Byte]
  /** Return the private key as an hexadecimal [String]. */
  def toPrivateKeyHex: String
}
object SHA3EdDSAPrivateKey {
  import net.i2p.crypto.eddsa.math.GroupElement
  import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
  import net.i2p.crypto.eddsa.{EdDSAPrivateKey, Utils}
  import scala.util.Try
  import java.security.MessageDigest

  private case class impl(self: EdDSAPrivateKey) extends SHA3EdDSAPrivateKey {
    val seed: Array[Byte] = self.getSeed
    val h: Array[Byte] = self.getH
    val a: Array[Byte] = self.geta
    val A: GroupElement = self.getA
    def toPublicKeyBytes: Array[Byte] = self.getAbyte
    def toPublicKeyHex: String = Utils.bytesToHex(this.toPublicKeyBytes)
    def toPrivateKeyBytes: Array[Byte] = self.getH
    def toPrivateKeyHex: String = Utils.bytesToHex(this.toPrivateKeyBytes)
  }

  private lazy val spec = SHA3EdDSAParameter.spec

  private val b = 256

  /**
    * Create a [SHA3EdDSAPrivateKey] from a byte array.
    * @param seed is the private key
    */
  private def withSeed(seed: Array[Byte]): Try[SHA3EdDSAPrivateKey] = Try {
    if (seed.length != b/8) throw new IllegalArgumentException("seed length is wrong")

    val hash = MessageDigest.getInstance("SHA-512")
    val h = hash.digest(seed)
    // FIXME: are these bitflips the same for any hash function?
    h(0) = (h(0) & 248.toByte).toByte
    h((b/8)-1) = (h((b/8)-1) & 63.toByte).toByte
    h((b/8)-1) = (h((b/8)-1) | 64.toByte).toByte
    val a = java.util.Arrays.copyOfRange(h, 0, b/8)
    val A = spec.getB.scalarMultiply(a)

    new impl(
      new EdDSAPrivateKey(
        new EdDSAPrivateKeySpec(seed, h, a, A, spec)))
  }

  /**
    * Initialize directly from the hash.
    *
    * @param h    the private key
    * @throws IllegalArgumentException if hash length is wrong
    * @since 0.1.1
    */
  def apply(h: Array[Byte]): Try[SHA3EdDSAPrivateKey]  = Try {
    if (h.length != b/4) throw new IllegalArgumentException(s"hash length is wrong ${b/4} != ${h.length}")

    h(0) = (h(0) & 248.toByte).toByte
    h((b/8)-1) = (h((b/8)-1) & 63.toByte).toByte
    h((b/8)-1) = (h((b/8)-1) | 64.toByte).toByte

    val a = util.Arrays.copyOfRange(h, 0, b/8)
    val A = spec.getB.scalarMultiply(a)

    new impl(
      new EdDSAPrivateKey(
        new EdDSAPrivateKeySpec(null, h, a, A, spec)))
  }

  /**
    * Create a [SHA3EdDSAPrivateKey] from a [String].
    * @param seed is the private key
    */
  def apply(seed: String): Try[SHA3EdDSAPrivateKey] =
    apply(Utils.hexToBytes(seed))


  def random: Try[SHA3EdDSAPrivateKey] =
    makeSeed
      .flatMap(withSeed)

  private def makeSeed: Try[Array[Byte]] = Try {
    val seed = Array.fill[Byte](32) {0x0}
    new scala.util.Random(new java.security.SecureRandom).nextBytes(seed)
    seed
  }
}
