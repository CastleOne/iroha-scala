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

sealed trait SHA3EdDSAPublicKey {
  import jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey
  import scala.util.Try
  import java.nio.charset.Charset
  val ctx: SHA3EdDSAContext
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
object SHA3EdDSAPublicKey {
  import Implicits._
  import jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey
  import scala.util.Try

  private case class impl(ctx: SHA3EdDSAContext, inner: EdDSAPublicKey) extends SHA3EdDSAPublicKey {
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
  def apply(publicKey: EdDSAPublicKey)(implicit ctx: SHA3EdDSAContext): Try[SHA3EdDSAPublicKey] = Try {
    impl(ctx, publicKey)
  }

  /**
    * Create a [SHA3EdDSAPublicKey] from a [String].
    * @param seed is the public key
    */
  def apply(seed: String)(implicit ctx: SHA3EdDSAContext): Try[SHA3EdDSAPublicKey] =
    apply(seed.bytes)

  /**
    * Create a [SHA3EdDSAPublicKey] from a byte array.
    * @param seed the private key
    */
  def apply(seed: Array[Byte])(implicit ctx: SHA3EdDSAContext): Try[SHA3EdDSAPublicKey] = Try {
    import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec
    assume(seed.length == 32)
    assume(seed.hexa.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
    new impl(
      ctx,
      new EdDSAPublicKey(
        new EdDSAPublicKeySpec(seed, ctx.spec)))
  }
}
