package net.cimadai.iroha

import io.grpc.{ManagedChannel, ManagedChannelBuilder}
import iroha.protocol.endpoint._
import iroha.protocol.primitive.RolePermission
import net.cimadai.iroha.Iroha._
import net.cimadai.iroha.Tags.TxTest
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.scalatest.AsyncWordSpec

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.{Await, Future}

class IrohaSpec extends AsyncWordSpec {
  import TestHelpers._
  import Iroha.MatchedResponse._

  private implicit val context = IrohaTestContext(
    sys.env.getOrElse("GRPC_HOST", "127.0.0.1"),
    sys.env.getOrElse("GRPC_PORT", "50051").toInt,
    adminPrivateKey = "f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70",
    adminPublicKey = "313a07e6384776ed95447710d15e59148473ccfc052a681317a72a69f2a49910",
    sys.env.getOrElse("VERBOSE_TX", "false").toBoolean
  )

  private implicit val channel: ManagedChannel = ManagedChannelBuilder.forAddress(context.grpcHost, context.grpcPort)
    .usePlaintext(true)
    .build()
  private implicit val commandGrpc: CommandServiceGrpc.CommandServiceBlockingStub = CommandServiceGrpc.blockingStub(channel)
  private implicit val queryGrpc: QueryServiceGrpc.QueryServiceBlockingClient = QueryServiceGrpc.blockingStub(channel)

  "Iroha" when {
    "verify" should {
      "sign and verify run right with create new key pair" in {
        val sha3_256 = new SHA3.Digest256()
        val message = "This is test string".getBytes()
        val messageHash = sha3_256.digest(message)

        val keyPair = Iroha.createNewKeyPair()
        val keyPair2 = keyPair.toHex.toKey

        // sign by keyPair and verify by keyPair
        assert(Iroha.verify(keyPair, Iroha.sign(keyPair, messageHash), messageHash), true)

        // sign by keyPair and verify by keyPair2
        assert(Iroha.verify(keyPair2, Iroha.sign(keyPair, messageHash), messageHash), true)
      }
      "sign and verify run right with load from private key" in {
        val sha3_256 = new SHA3.Digest256()
        val message = "This is test string".getBytes()
        val messageHash = sha3_256.digest(message)

        val keyPair = context.adminAccount.keypair
        val keyPair2 = keyPair.toHex.toKey

        // sign by keyPair and verify by keyPair
        assert(Iroha.verify(keyPair, Iroha.sign(keyPair, messageHash), messageHash), true)

        // sign by keyPair and verify by keyPair2
        assert(Iroha.verify(keyPair2, Iroha.sign(keyPair, messageHash), messageHash), true)
      }
  }
    "CommandService" when {
      "create a new account" taggedAs TxTest in {
        val domain = IrohaDomainName(context.testDomain)
        val user1Name = IrohaAccountName(createRandomName(10))
        val user1Id = IrohaAccountId(user1Name, domain)

        val user1keyPair = Iroha.createNewKeyPair()
        val createAccount = Iroha.CommandService.createAccount(user1keyPair.publicKey, user1Name, domain)
        val transaction = Iroha.CommandService.createTransaction(context.adminAccount.accountId, context.adminAccount.keypair, Seq(createAccount))
        val accountQuery = Iroha.QueryService.getAccount(context.adminAccount.accountId, context.adminAccount.keypair, user1Id)
        println(TestFormatter.command(createAccount))
        for {
          sent <- sendTransaction(transaction)
          committed <- Future(sent).collect({ case true => awaitUntilTransactionCommitted(transaction) })
          query <- Future(committed).collect({ case true => sendQuery(accountQuery) })
          account = Some(query).collect({ case Iroha.QueryResponse(AccountResponse(x)) => x }).flatMap(_.account)
        } yield {
          println(TestFormatter.queryResponse(query))
          assert(sent, true)
          assert(committed, true)
          assert(account.map(_.accountId.split("@").head).contains(user1Name.value))
          assert(account.map(_.domainId).contains(domain.value))
        }
      }

      "create a new role" taggedAs TxTest in {
        val roleName = createRandomAlphaName(7)
        val permissions = Seq(RolePermission.can_append_role, RolePermission.can_transfer)
        val roleId = IrohaRoleId(IrohaRoleName(roleName))

        val createRole = Iroha.CommandService.createRole(roleName, permissions)
        val transaction = Iroha.CommandService.createTransaction(context.adminAccount.accountId, context.adminAccount.keypair, Seq(createRole))
        val rolesQuery = Iroha.QueryService.getRoles(context.adminAccount.accountId, context.adminAccount.keypair)
        val rolePermissions = Iroha.QueryService.getRolePermissions(context.adminAccount.accountId, context.adminAccount.keypair, roleId)
        println(TestFormatter.command(createRole))
        for {
          sent <- sendTransaction(transaction)
          committed <- Future(sent).collect({ case true => awaitUntilTransactionCommitted(transaction) })
          rolesQuery <- Future(committed).collect({ case true => sendQuery(rolesQuery) })
          roles = Some(rolesQuery).collect({ case Iroha.QueryResponse(RolesResponse(x)) => x.roles })
          permissionsQuery <- Future(committed).collect({ case true => sendQuery(rolePermissions) })
          responsePermissions = Some(permissionsQuery).collect({ case Iroha.QueryResponse(RolePermissions(x)) => x.permissions })
        } yield {
          println(TestFormatter.queryResponse(rolesQuery))
          println(TestFormatter.queryResponse(permissionsQuery))
          assert(sent, true)
          assert(committed, true)
          assert(roles.exists(_.contains(roleName)))
          assert(responsePermissions.map(_.toList).contains(permissions))
        }
      }

      "append a new role to account" taggedAs TxTest in {
        // Create Account
        val domain = IrohaDomainName(context.testDomain)
        val user1Name = IrohaAccountName(createRandomName(10))
        val user1Id = IrohaAccountId(user1Name, domain)

        val user1keyPair = Iroha.createNewKeyPair()
        val createAccount = Iroha.CommandService.createAccount(user1keyPair.publicKey, user1Name, domain)
        println(TestFormatter.command(createAccount))

        // Create Role
        val roleName = createRandomAlphaName(7)
        val permissions = Seq(RolePermission.can_append_role, RolePermission.can_get_roles, RolePermission.can_transfer)

        val createRole = Iroha.CommandService.createRole(roleName, permissions)
        println(TestFormatter.command(createRole))

        // Append that Role
        val appendRole = Iroha.CommandService.appendRole(user1Id, roleName)
        println(TestFormatter.command(appendRole))

        val commands = Seq(createAccount, createRole, appendRole)
        val transaction = Iroha.CommandService.createTransaction(context.adminAccount.accountId, context.adminAccount.keypair, commands)
        val rolesQuery = Iroha.QueryService.getRoles(user1Id, user1keyPair)

        for {
          sent <- sendTransaction(transaction)
          committed <- Future(sent).collect({ case true => awaitUntilTransactionCommitted(transaction) })
          rolesQuery <- Future(committed).collect({ case true => sendQuery(rolesQuery) })
          roles = Some(rolesQuery).collect({ case Iroha.QueryResponse(RolesResponse(x)) => x.roles })
        } yield {
          println(TestFormatter.queryResponse(rolesQuery))
          assert(sent, true)
          assert(committed, true)
          assert(roles.exists(_.contains(roleName)))
        }
      }
    }
  }
}
