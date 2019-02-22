package net.cimadai.iroha

import iroha.protocol.primitive
import net.cimadai.iroha.Iroha.{Domain, Account, Asset, Role, Amount, Description}
import net.i2p.crypto.eddsa.Utils

object IrohaImplicits {
  implicit def formatDomain(value: Domain): String = value.toString
  implicit def formatAccount(value: Account): String = value.toString
  implicit def formatAsset(value: Asset): String = value.toString
  implicit def formatRole(value: Role): String = value.toString
  implicit def formatAmount(value: Amount): String = value.toString
  implicit def formatDescription(value: Description): String = value.toString
  //FIXME: implicit def primitivePeer(peer: Peer): primitive.Peer = primitive.Peer(peer.address, Utils.bytesToHex(peer.publicKey.getAbyte))
  //FIXME: implicit def maybePrimitivePeer(peer: Option[Peer]): Option[primitive.Peer] = peer.map(implicitly(_))
}
