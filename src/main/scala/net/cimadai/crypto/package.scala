package net.cimadai

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

package object crypto {

  //XXX
  //XXX private val ed25519field: Field =
  //XXX   new Field(
  //XXX     256, // b
  //XXX     Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
  //XXX     new Ed25519LittleEndianEncoding())
  //XXX
  //XXX private val ed25519curve: Curve =
  //XXX   new Curve(ed25519field,
  //XXX     Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
  //XXX     ed25519field.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))) // I
  //XXX
  //XXX
  //XXX private val ed25519_256: EdDSANamedCurveSpec =
  //XXX   new EdDSANamedCurveSpec(
  //XXX     "Ed25519_256",
  //XXX     ed25519curve,
  //XXX     "SHA-512", // H
  //XXX     new Ed25519ScalarOps(), // l
  //XXX     ed25519curve.createPoint( // B
  //XXX       Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
  //XXX       true)) // Precompute tables for B
  //XXX assert(ed25519_256 != null)
  //XXX
  //XXX EdDSANamedCurveTable.defineCurve(ed25519_256)
  //XXX val spec = EdDSANamedCurveTable.getByName("Ed25519_256")

  //XXX import org.bouncycastle.jcajce.provider.digest.SHA3
  //XXX val digest = new SHA3.Digest256
  //XXX val hash: MessageDigest = MessageDigest.getInstance(digest.getAlgorithm)
  //XXX
  //XXX val engine = new EdDSAEngine(digest)
  //XXX
  //XXX private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
  //XXX private val ed25519_SHA3_256: EdDSANamedCurveSpec =
  //XXX   new EdDSANamedCurveSpec(
  //XXX     "Ed25519_SHA3_256",
  //XXX     ed25519.getCurve,
  //XXX     digest.getAlgorithm, // H
  //XXX     ed25519.getScalarOps, // l
  //XXX     ed25519.getB) // B
  //XXX
  //XXX val spec = ed25519_SHA3_256
  //XXX assume(spec.getCurve.getField.getb == 256)
  //XXX assume(spec.getHashAlgorithm == digest.getAlgorithm)
  //XXX assert(false)

}
