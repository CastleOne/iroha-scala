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

import acyclic.pkg

sealed trait PublicKey {
  import jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey
  import scala.util.Try
  import java.nio.charset.Charset
  val ctx: Crypto
  val inner: EdDSAPublicKey
  /** Returns the public key as a byte array. */
  def bytes: Array[Byte]
  /** Returns the public key as an hexadecimal String. */
  def hexa: String
  /** Verifies a message [String] under a certain [Charset]. */
  def verify(signature: Array[Byte], message: String, charset: Charset): Try[Boolean]
  /** Verifies a message [String]. */
  def verify(signature: Array[Byte], message: String): Try[Boolean]
  /** Verifies a byte array. */
  def verify(signature: Array[Byte], bytes: Array[Byte]): Try[Boolean]
}
object PublicKey {
  import Implicits._
  import jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey
  import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec
  import scala.util.Try

  private case class impl(ctx: Crypto, inner: EdDSAPublicKey) extends PublicKey {
    import scala.util.Try
    import java.nio.charset.Charset
    import Implicits._
    def bytes: Array[Byte] = inner.getAbyte
    def hexa: String = bytes.hexa
    def verify(signature: Array[Byte], message: String, charset: Charset): Try[Boolean] = verify(signature, message.getBytes(charset))
    def verify(signature: Array[Byte], message: String): Try[Boolean] = verify(signature, message.getBytes)
    def verify(signature: Array[Byte], bytes: Array[Byte]): Try[Boolean] = Try {
      ctx.engine.initVerify(inner)
      ctx.engine.verifyOneShot(bytes, signature)
    }
  }

  /**
    * Create a [SHA3EdDSAPublicKey] from a [EdDSAPublicKey].
    * @param publicKey is the public key
    */
  def apply(publicKey: EdDSAPublicKey)(implicit context: Try[Crypto]): Try[PublicKey] =
    context.map(ctx => impl(ctx, publicKey))

  /**
    * Create a [SHA3EdDSAPublicKey] from a [String].
    * @param seed is the public key
    */
  def apply(seed: String)(implicit context: Try[Crypto]): Try[PublicKey] =
    apply(seed.bytes)

  /**
    * Create a [SHA3EdDSAPublicKey] from a byte array.
    * @param seed the private key
    */
  def apply(seed: Array[Byte])(implicit context: Try[Crypto]): Try[PublicKey] =
    context.map(ctx =>
      impl(ctx,
        new EdDSAPublicKey(
          new EdDSAPublicKeySpec(seed, ctx.spec))))
}
