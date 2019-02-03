package net.cimadai.iroha

/**
  * Copyright Daisuke SHIMADA All Rights Reserved.
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

import java.util.concurrent.atomic.AtomicLong

import com.google.protobuf.ByteString
import iroha.protocol.transaction.Transaction
import iroha.protocol.commands.Command
import iroha.protocol.commands.Command.Command._
import iroha.protocol.endpoint.{ToriiResponse, TxStatus, TxStatusRequest}
import iroha.protocol.primitive._
import iroha.protocol.queries.Query
import iroha.protocol.{commands, queries}
import net.cimadai.crypto.{SHA3EdDSAParameterSpec, SHA3EdDSAPrivateKeySpec}
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, Utils}
import org.bouncycastle.jcajce.provider.digest.SHA3

object Iroha {
  private val queryCounter = new AtomicLong(1)

  implicit class EdDSAPublicKeyExt(pub: EdDSAPublicKey) {
    def toPublicKeyBytes: Array[Byte] = pub.getAbyte

    def toPublicKeyHex: String = Utils.bytesToHex(pub.toPublicKeyBytes)
  }

  implicit class EdDSAPrivateKeyExt(priv: EdDSAPrivateKey) {
    def toPublicKeyBytes: Array[Byte] = priv.getAbyte

    def toPublicKeyHex: String = Utils.bytesToHex(priv.toPublicKeyBytes)

    def toPrivateKeyBytes: Array[Byte] = priv.getH

    def toPrivateKeyHex: String = Utils.bytesToHex(priv.toPrivateKeyBytes)
  }

  case class Ed25519KeyPair(privateKey: EdDSAPrivateKey, publicKey: EdDSAPublicKey) {
    def toHex: Ed25519KeyPairHex = Ed25519KeyPairHex(privateKey.toPrivateKeyHex)
  }

  object Ed25519KeyPairHex {
    def apply (privateKeyHex: String): Ed25519KeyPairHex = {
      Ed25519KeyPairHex(Utils.hexToBytes(privateKeyHex))
    }
  }

  case class Ed25519KeyPairHex(privateKeyBytes: Array[Byte]) {
    private val sKey = new EdDSAPrivateKey(SHA3EdDSAPrivateKeySpec(spec, privateKeyBytes))
    private val pKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(sKey.toPublicKeyBytes, spec))

    val publicKey: String = sKey.toPublicKeyHex
    val privateKey: String = sKey.toPrivateKeyHex

    def toKey: Ed25519KeyPair =
      Ed25519KeyPair(sKey, pKey)
  }

  case class ToriiError(message: String, txStatus: TxStatus) extends Error(message)

  object ToriiError {
    def unapply(response: ToriiResponse): Option[ToriiError] = (response.errorMessage, response.txStatus) match {
      case (msg, TxStatus.STATELESS_VALIDATION_FAILED) => Some(ToriiError(s"Stateless Validation Failed: $msg", response.txStatus))
      case (msg, TxStatus.STATEFUL_VALIDATION_FAILED) => Some(ToriiError(s"Stateful Validation Failed: $msg", response.txStatus))
      case (msg, TxStatus.NOT_RECEIVED) => Some(ToriiError(s"Transaction Not Received: $msg", response.txStatus))
      case (msg, TxStatus.MST_EXPIRED) => Some(ToriiError(s"MST Expired: $msg", response.txStatus))
      case _ => None
    }
  }

  case class IrohaDomainName(value: String) {
    assert(0 < value.length && value.length <= 164, "domainName length must be between 1 to 164")
    assert(IrohaValidator.isValidDomain(value), "domainName must satisfy the domain specifications (RFC1305).")
  }

  case class IrohaAssetName(value: String) {
    assert(0 < value.length && value.length <= 9, "assetName length must be between 1 to 9")
    assert(IrohaValidator.isAlphabetAndNumber(value), "assetName must be only alphabet or number. [a-zA-Z0-9]")
  }

  case class IrohaAccountName(value: String) {
    assert(0 < value.length && value.length <= 32, "accountName length must be between 1 to 32")
    assert(IrohaValidator.isAplhaNumberUnderscore(value), "accountName can only be alpha numeric plus a underscore. [a-z_0-9]")
    assert(IrohaValidator.isValidDomain(value.replaceAll("_", "")), "accountName must satisfy the domain specifications (RFC1305).")
  }

  case class IrohaRoleName(value: String) {
    assert(0 < value.length && value.length <= 7, "roleName length must be between 1 to 7")
    assert(IrohaValidator.isAlphabetAndNumber(value) && IrohaValidator.isLowerCase(value), "roleName must be only lower alphabet. [a-z]")
  }

  case class IrohaAssetPrecision(value: Int) {
    assert(0 <= value && value <= 255, "precision must be between 0 to 255")
  }

  case class IrohaTransferDescription(value: String) {
    assert(64 <= value.length, "transferDescription size should be less than or equal to 64")
    override def toString: String = value
  }

  case class IrohaAccountId(accountName: IrohaAccountName, domain: IrohaDomainName) {
    override def toString: String = s"${accountName.value}@${domain.value}"
  }

  case class IrohaAssetId(assetName: IrohaAssetName, domain: IrohaDomainName) {
    override def toString: String = s"${assetName.value}#${domain.value}"
  }

  case class IrohaRoleId(roleName: IrohaRoleName) {
    override def toString: String = s"${roleName.value}"
  }

  case class IrohaAmount(value: String, precision: IrohaAssetPrecision) {
    private val isZeroOrPositive = BigDecimal(value) >= 0
    assert(isZeroOrPositive, "amount must be greater equal than 0")
  }

  case class IrohaPeer(address: String, publicKey: EdDSAPublicKey) {
    def byteString: ByteString = ByteString.copyFrom(publicKey.toPublicKeyBytes)
  }

  private val spec = new SHA3EdDSAParameterSpec

  private def withEd25519[T](f: EdDSAEngine => T): T = {
    val signature = new EdDSAEngine(new SHA3.Digest512())
    f(signature)
  }

  def createNewKeyPair(): Ed25519KeyPair = {
    val seed = Array.fill[Byte](32) {0x0}
    new scala.util.Random(new java.security.SecureRandom()).nextBytes(seed)
    val sKey = new EdDSAPrivateKey(SHA3EdDSAPrivateKeySpec(seed, spec))
    val vKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(sKey.toPublicKeyBytes, spec))
    Ed25519KeyPair(sKey, vKey)
  }

  def createKeyPairFromHex(privateKeyHex: String): Ed25519KeyPair = {
    Ed25519KeyPairHex(privateKeyHex).toKey
  }

  def createKeyPairFromBytes(privateKeyBytes: Array[Byte]): Ed25519KeyPair = {
    Ed25519KeyPairHex(privateKeyBytes).toKey
  }

  def sign(keyPair: Ed25519KeyPair, message: Array[Byte]): Array[Byte] = {
    withEd25519 { ed25519 =>
      ed25519.initSign(keyPair.privateKey)
      ed25519.signOneShot(message)
    }
  }

  def verify(keyPair: Ed25519KeyPair, signature: Array[Byte], message: Array[Byte]): Boolean = {
    withEd25519 { ed25519 =>
      ed25519.initVerify(keyPair.publicKey)
      ed25519.verifyOneShot(message, signature)
    }
  }

  object CommandService {
    import IrohaImplicits._

    private def txHash(transaction: Transaction): Array[Byte] = {
      new SHA3.Digest256().digest(transaction.payload.get.toByteArray)
    }

    def createTransaction(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, commands: Seq[Command]): Transaction = {
      val createdTime = System.currentTimeMillis()

      val maybeReducedPayload = commands.headOption
        .map(_ => Transaction.Payload.ReducedPayload(commands, creatorAccountId, createdTime, 1))

      val payload = Transaction.Payload(reducedPayload = maybeReducedPayload)

      val sha3_256 = new SHA3.Digest256()
      val hash = sha3_256.digest(payload.toByteArray)
      val sig = Signature(
        ByteString.copyFrom(creatorKeyPair.publicKey.toPublicKeyBytes),
        ByteString.copyFrom(Iroha.sign(creatorKeyPair, hash))
      )
      Transaction(Some(payload), Seq(sig))
    }

    def appendRole(accountId: IrohaAccountId, roleName: String): Command =
      Command(AppendRole(commands.AppendRole(accountId, roleName)))

    def createRole(roleName: String, permissions: Seq[RolePermission]): Command =
      Command(CreateRole(commands.CreateRole(roleName, permissions)))

    def grantPermission(accountId: IrohaAccountId, permissions: GrantablePermission): Command =
      Command(GrantPermission(commands.GrantPermission(accountId, permissions)))

    def revokePermission(accountId: IrohaAccountId, permissions: GrantablePermission): Command =
      Command(RevokePermission(commands.RevokePermission(accountId, permissions)))

    def addAssetQuantity(assetId: IrohaAssetId, amount: IrohaAmount): Command =
      Command(AddAssetQuantity(commands.AddAssetQuantity(assetId, amount.value)))

    def addPeer(peer: Option[IrohaPeer]): Command =
      Command(AddPeer(commands.AddPeer(peer)))

    def addSignatory(accountId: IrohaAccountId, publicKey: EdDSAPublicKey): Command =
      Command(AddSignatory(commands.AddSignatory(accountId, ByteString.copyFrom(publicKey.toPublicKeyBytes))))

    def createAccount(publicKey: EdDSAPublicKey, accountName: IrohaAccountName, domainName: IrohaDomainName): Command =
      Command(CreateAccount(commands.CreateAccount(accountName.value, domainName.value, mainPubkey = ByteString.copyFrom(publicKey.toPublicKeyBytes))))

    def createAsset(assetName: IrohaAssetName, domainName: IrohaDomainName, precision: IrohaAssetPrecision): Command =
      Command(CreateAsset(commands.CreateAsset(assetName.value, domainName.value, precision.value)))

    def createDomain(domainName: IrohaDomainName, defaultRoleName: String): Command =
      Command(CreateDomain(commands.CreateDomain(domainName.value, defaultRoleName)))

    def removeSignatory(accountId: IrohaAccountId, publicKey: EdDSAPublicKey): Command =
      Command(RemoveSign(commands.RemoveSignatory(accountId, ByteString.copyFrom(publicKey.toPublicKeyBytes))))

    def setQuorum(accountId: IrohaAccountId, quorum: Int): Command =
      Command(SetQuorum(commands.SetAccountQuorum(accountId, quorum)))

    def subtractAssetQuantity(assetId: IrohaAssetId, amount: IrohaAmount): Command =
      Command(SubtractAssetQuantity(commands.SubtractAssetQuantity(assetId, amount.value)))

    def transferAsset(srcAccountId: IrohaAccountId, destAccountId: IrohaAccountId, assetId: IrohaAssetId, description: IrohaTransferDescription, amount: IrohaAmount): Command =
      Command(TransferAsset(commands.TransferAsset(
        srcAccountId,
        destAccountId,
        assetId,
        description,
        amount.value)))

    def txStatusRequest(transaction: Transaction): TxStatusRequest =
      TxStatusRequest(ByteString.copyFrom(Iroha.CommandService.txHash(transaction)))
  }

  object QueryService {
    import IrohaImplicits._

    private def createQuery(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, query: Query.Payload.Query): Query = {
      val createdTime = System.currentTimeMillis()

      val payload = Query.Payload(
        meta = Some(queries.QueryPayloadMeta(
          createdTime = createdTime,
          creatorAccountId = creatorAccountId,
          queryCounter = queryCounter.getAndIncrement()
        )),
        query = query
      )

      val sha3_256 = new SHA3.Digest256()
      val hash = sha3_256.digest(payload.toByteArray)
      val sig = Signature(
        ByteString.copyFrom(creatorKeyPair.publicKey.toPublicKeyBytes),
        ByteString.copyFrom(Iroha.sign(creatorKeyPair, hash))
      )
      Query(Some(payload), Some(sig))
    }

    def getAccount(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, accountId: IrohaAccountId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAccount(queries.GetAccount(accountId.toString)))
    }

    def getSignatories(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, accountId: IrohaAccountId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAccountSignatories(queries.GetSignatories(accountId.toString)))
    }

    def getAccountTransactions(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, accountId: IrohaAccountId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAccountTransactions(queries.GetAccountTransactions(accountId.toString)))
    }

    def getAccountAssetTransactions(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, accountId: IrohaAccountId, assetId: IrohaAssetId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAccountAssetTransactions(queries.GetAccountAssetTransactions(accountId.toString, assetId.toString)))
    }

    def getTransactions(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, txHashes: Seq[Array[Byte]]): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetTransactions(queries.GetTransactions(txHashes.map(c => ByteString.copyFrom(c)))))
    }

    def getAccountAssets(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, accountId: IrohaAccountId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAccountAssets(queries.GetAccountAssets(accountId)))
    }

    def getAccountDetail(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, accountId: IrohaAccountId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAccount(queries.GetAccount(accountId.toString)))
    }

    def getRoles(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetRoles(queries.GetRoles()))
    }

    def getRolePermissions(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, roleId: IrohaRoleId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetRolePermissions(queries.GetRolePermissions(roleId.toString)))
    }

    def getAssetInfo(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair, assetId: IrohaAssetId): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetAssetInfo(queries.GetAssetInfo(assetId.toString)))
    }

    def getPendingTransactions(creatorAccountId: IrohaAccountId, creatorKeyPair: Ed25519KeyPair): Query = {
      createQuery(creatorAccountId, creatorKeyPair, Query.Payload.Query.GetPendingTransactions(queries.GetPendingTransactions()))
    }
  }

  sealed trait MatchedResponse

  object MatchedResponse {
    import iroha.protocol.{qry_responses => Responses}
    case class AccountAssetsResponse(response: Responses.AccountAssetResponse) extends MatchedResponse
    case class AccountDetailResponse(response: Responses.AccountDetailResponse) extends MatchedResponse
    case class AccountResponse(response: Responses.AccountResponse) extends MatchedResponse
    case class ErrorResponse(response: Responses.ErrorResponse) extends MatchedResponse
    case class SignatoriesResponse(response: Responses.SignatoriesResponse) extends MatchedResponse
    case class TransactionsResponse(response: Responses.TransactionsResponse) extends MatchedResponse
    case class AssetResponse(response: Responses.AssetResponse) extends MatchedResponse
    case class RolesResponse(response: Responses.RolesResponse) extends MatchedResponse
    case class RolePermissionsResponse(response: Responses.RolePermissionsResponse) extends MatchedResponse
  }

  object QueryResponse {
    import iroha.protocol.qry_responses.QueryResponse
    import MatchedResponse._

    def unapply(arg: QueryResponse): Option[MatchedResponse] = arg.response match {
      case r if r.isAccountAssetsResponse => arg.response.accountAssetsResponse.map(AccountAssetsResponse.apply)
      case r if r.isAccountDetailResponse => arg.response.accountDetailResponse.map(AccountDetailResponse.apply)
      case r if r.isAccountResponse => arg.response.accountResponse.map(AccountResponse.apply)
      case r if r.isErrorResponse => arg.response.errorResponse.map(ErrorResponse.apply)
      case r if r.isSignatoriesResponse => arg.response.signatoriesResponse.map(SignatoriesResponse.apply)
      case r if r.isTransactionsResponse => arg.response.transactionsResponse.map(TransactionsResponse.apply)
      case r if r.isAssetResponse => arg.response.assetResponse.map(AssetResponse.apply)
      case r if r.isRolesResponse => arg.response.rolesResponse.map(RolesResponse.apply)
      case r if r.isRolePermissionsResponse => arg.response.rolePermissionsResponse.map(RolePermissionsResponse.apply)
      case _ => None
    }
  }
}
