package net.cimadai.crypto

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

import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.spec.{EdDSAParameterSpec, EdDSAPrivateKeySpec}
import java.security.{MessageDigest, NoSuchAlgorithmException}


trait SHA3EdDSAPrivateKey {
  val seed: Array[Byte]
  val h: Array[Byte]
  val a: Array[Byte]
  val A: GroupElement
  def toPublicKeyBytes: Array[Byte]
  def toPublicKeyHex: String
  def toPrivateKeyBytes: Array[Byte]
  def toPrivateKeyHex: String
}
object SHA3EdDSAPrivateKey {
  import net.i2p.crypto.eddsa.EdDSAPrivateKey
  import net.i2p.crypto.eddsa.Utils
  import scala.util.Try

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
    * @param seed the private key
    * @throws IllegalArgumentException if seed length is wrong or hash algorithm is unsupported
    */
  def apply(seed: Array[Byte]): Try[SHA3EdDSAPrivateKey] = Try {
    if (seed.length != b/8) {
      throw new IllegalArgumentException("seed length is wrong")
    }

    try {
      val hash = MessageDigest.getInstance("SHA-512")

      // H(k)
      val h = hash.digest(seed)
      //edDsaPrivateKeySha3_256Spec.h = hash.digest(seed)

      /*a = BigInteger.valueOf(2).pow(b-2);
      for (int i=3;i<(b-2);i++) {
          a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(Utils.bit(h,i))));
      }*/
      // Saves ~0.4ms per key when running signing tests.
      // TODO: are these bitflips the same for any hash function?
      h(0) = (h(0) & 248.toByte).toByte
      h((b/8)-1) = (h((b/8)-1) & 63.toByte).toByte
      h((b/8)-1) = (h((b/8)-1) | 64.toByte).toByte
      val a = java.util.Arrays.copyOfRange(h, 0, b/8)
      val A = spec.getB.scalarMultiply(a)

      new impl(
        new EdDSAPrivateKey(
          new EdDSAPrivateKeySpec(seed, h, a, A, spec)))
    } catch {
      case _: NoSuchAlgorithmException =>
        throw new IllegalArgumentException("Unsupported hash algorithm")
    }
  }

  //XXX /**
  //XXX   * Initialize directly from the hash.
  //XXX   * getSeed() will return null if this constructor is used.
  //XXX   *
  //XXX   * @param spec the parameter specification for this key
  //XXX   * @param h    the private key
  //XXX   * @throws IllegalArgumentException if hash length is wrong
  //XXX   * @since 0.1.1
  //XXX   */
  //XXX def apply(spec: EdDSAParameterSpec, h: Array[Byte]): Try[SHA3EdDSAPrivateKey] = Try {
  //XXX   if (h.length != b/4)
  //XXX     throw new IllegalArgumentException("hash length is wrong")
  //XXX
  //XXX   h(0) = (h(0) & 248.toByte).toByte
  //XXX   h((b/8)-1) = (h((b/8)-1) & 63.toByte).toByte
  //XXX   h((b/8)-1) = (h((b/8)-1) | 64.toByte).toByte
  //XXX
  //XXX   val a = java.util.Arrays.copyOfRange(h, 0, b/8)
  //XXX   val A = spec.getB.scalarMultiply(a)
  //XXX
  //XXX   new impl(
  //XXX     new EdDSAPrivateKey(
  //XXX       new EdDSAPrivateKeySpec(null, h, a, A, spec)))
  //XXX }

}
