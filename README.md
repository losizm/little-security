# little-security

[![Maven Central](https://img.shields.io/maven-central/v/com.github.losizm/little-security_3.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.github.losizm%22%20AND%20a:%22little-security_3%22)

The Scala library that adds a little security to applications.

_This project is archived and read-only. See [Ergo](https://github.com/losizm/ergo) for active fork._

## Table of Contents
- [Getting Started](#Getting-Started)
- [How It Works](#How-It-Works)
  - [Security in Action](#Security-in-Action)
- [Permission](#Permission)
  - [User and Group Permissions](#User-and-Group-Permissions)
- [Security Context](#Security-Context)
  - [Granting Any or All Permissions](#Granting-Any-or-All-Permissions)
  - [Testing Permissions](#Testing-Permissions)
  - [Automatic User and Group Permissions](#Automatic-User-and-Group-Permissions)
  - [The Omnipotent Root Context](#The-Omnipotent-Root-Context)
- [API Documentation](#API-Documentation)
- [License](#License)


## Getting Started
To get started, add **little-security** to your library dependencies.

```scala
libraryDependencies += "com.github.losizm" %% "little-security" % "1.1.0"
```

_**NOTE:** Starting with version 1, **little-security** is written for Scala 3
exclusively. See previous releases for compatibility with Scala 2.12 and Scala
2.13._

## How It Works

**little-security** is powered by a pair of traits: `Permission` and
`SecurityContext`.

A `Permission` is defined with a given name, and one or more permissions can be
applied to a restricted operation.

A `SecurityContext` establishes a pattern in which a restricted operation is
performed only if its required permissions are granted; otherwise, a
`SecurityViolation` is raised.

### Security in Action

The following script demonstrates how read/write access to an in-memory cache
could be implemented.

```scala
import little.security.{ Permission, SecurityContext, UserContext }

import scala.collection.concurrent.TrieMap

object SecureCache:
  // Define permissions for reading and writing cache entries
  private val getPermission = Permission("cache:get")
  private val putPermission = Permission("cache:put")

  private val cache = TrieMap[String, String](
    "gang starr"      -> "step in the arena",
    "digable planets" -> "blowout comb"
  )

  def get(key: String)(using security: SecurityContext): String =
    // Test for read permission before getting cache entry
    security(getPermission) { cache(key) }

  def put(key: String, value: String)(using security: SecurityContext): Unit =
    // Test for write permission before putting cache entry
    security(putPermission) { cache += key -> value }

// Set security context for user with read permission to cache
given SecurityContext = UserContext("losizm", "staff", Permission("cache:get"))

// Get cache entry
val classic = SecureCache.get("gang starr")

// Throw SecurityViolation because user lacks write permission
SecureCache.put("sucker mc", classic)
```

## Permission

A `Permission` is identified by its name, and you're free to implement any
convention for the names.

The following defines 3 permissions, any of which could be used as a
permission for read access to an archive module.

```scala
val perm1 = Permission("archive:read")
val perm2 = Permission("module=archive; access=read")
val perm3 = Permission("[[GET]] /api/modules/archive")
```

### User and Group Permissions

A user permission is created with `UserPermission`. There's no implementing
class: It's just a factory. It constructs a permission with a specially
formatted name using a user identifier.

```scala
import little.security.UserPermission

val userPermission = UserPermission("losizm")

// Destructure permission to its user identifier
userPermission match
  case UserPermission(userId) => println(s"uid=$userId")
  case perm                   => throw Exception(s"Unexpected permission: ${perm.name}")
```

And `GroupPermission` constructs a permission with a specially formatted name
using a group identifier.

```scala
import little.security.GroupPermission

val groupPermission = GroupPermission("staff")

// Destructure permission to its group identifier
groupPermission match
  case GroupPermission(groupId) => println(s"gid=$groupId")
  case perm                     => throw Exception(s"Unexpected permission: ${perm.name}")
```

See also [Automatic User and Group Permissions](#Automatic-User-and-Group-Permissions).

## Security Context

A `SecurityContext` is consulted for authorization to apply a restricted
operation. If authorized, the operation is applied; otherwise, the security
context raises a `SecurityViolation`.

`UserContext` is an implementation of a security context. It is constructed
with supplied user and group identifiers along with a set of granted
permissions.

```scala
import little.security.{ Permission, SecurityContext, UserContext }

object BuildManager:
  private val buildPermission      = Permission("action=build")
  private val deployDevPermission  = Permission("action=deploy; env=dev")
  private val deployProdPermission = Permission("action=deploy; env=prod")

  def build(project: String)(using security: SecurityContext): Unit =
    // Test permission before building project
    security(buildPermission) {
      println(s"Build $project.")
    }

  def deployToDev(project: String)(using security: SecurityContext): Unit =
    // Test permission before deploying project
    security(deployDevPermission) {
      println(s"Deploy $project to dev environment.")
    }

  def deployToProd(project: String)(using security: SecurityContext): Unit =
    // Test permission before deploying project
    security(deployProdPermission) {
      println(s"Deploy $project to prod environment.")
    }

// Set security context for user with two permissions
given SecurityContext = UserContext("ishmael", "developer",
  Permission("action=build"),
  Permission("action=deploy; env=dev")
)

// Permission granted to build
BuildManager.build("my-favorite-app")

// Permission granted to deploy to dev
BuildManager.deployToDev("my-favorite-app")

// Permission not granted to deploy to prod -- throw SecurityViolation
BuildManager.deployToProd("my-favorite-app")
```

### Granting Any or All Permissions

`SecurityContext.any(Permission*)` is used to ensure that at least one of
supplied permissions is granted before an operation is applied.

`SecurityContext.all(Permission*)` is used to ensure that all supplied
permissions are granted before an operation is applied.

```scala
import little.security.{ Permission, SecurityContext, UserContext }

object FileManager:
  private val readOnlyPermission  = Permission("file:read-only")
  private val readWritePermission = Permission("file:read-write")
  private val encryptPermission   = Permission("file:encrypt")

  def read(fileName: String)(using security: SecurityContext): Unit =
    // Get either read-only or read-write permission before performing operation
    security.any(readOnlyPermission, readWritePermission) {
      println(s"Read $fileName.")
    }

  def encrypt(fileName: String)(using security: SecurityContext): Unit =
    // Get both read-write and encrypt permissions before performing operation
    security.all(readWritePermission, encryptPermission) {
      println(s"Encrypt $fileName.")
    }

// Set security context for read/write permission
given SecurityContext = UserContext("isaac", "ops", Permission("file:read-write"))

// Can read via read-write permission
FileManager.read("/etc/passwd")

// Has read-write but lacks encrypt permission -- throw SecurityViolation
FileManager.encrypt("/etc/passwd")
```

### Testing Permissions

Sometimes, it may be enough to simply test a permission to see whether it is
granted, and not necessarily throw a `SecurityViolation` if it isn't. That's
precisely what `SecurityContext.test(Permission)` is for. It returns `true` or
`false` based on the permission being granted or not. It's an ideal predicate to
a security filter, as demonstrated in the following script.

```scala
import little.security.{ Permission, SecurityContext, UserContext }

object SecureMessages:
  // Define class for text message with assigned permission
  private case class Message(text: String, permission: Permission)

  private val messages = Seq(
    Message("This is a public message."   , Permission("public")),
    Message("This is a protected message.", Permission("protected")),
    Message("This is a private message."  , Permission("private"))
  )

  def list(using security: SecurityContext): Seq[String] =
    // Filter messages by testing permission
    messages.filter(msg => security.test(msg.permission)).map(_.text)

// Set security context for user with "public" and "protected" permissions
given SecurityContext = UserContext("losizm", "staff",
  Permission("public"),
  Permission("protected")
)

// Print all accessible messages
SecureMessages.list.foreach(println)
```

### Automatic User and Group Permissions

When an instance of `UserContext` is created, user and group permissions are
added to the permissions expressly supplied in constructor.

```scala
val user = UserContext("losizm", "staff", Permission("read"))

assert(user.test(Permission("read")))
assert(user.test(UserPermission("losizm")))
assert(user.test(GroupPermission("staff")))
```

You may use these permissions in your application. For example, a document store
could be implemented giving a single user read/write permissions, while allowing
other users in her group read permission only.

```scala
import little.security.*

import scala.collection.concurrent.TrieMap

class DocumentStore(userId: String, groupId: String):
  private val userPermission  = UserPermission(userId)
  private val groupPermission = GroupPermission(groupId)

  private val storage = TrieMap[String, String]()

  def get(name: String)(using security: SecurityContext): String =
    // Anyone in group can retrieve document
    security(groupPermission) { storage(name) }

  def put(name: String, doc: String)(using security: SecurityContext): Unit =
    // Only owner can store document
    security(userPermission) { storage += name -> doc }

// Create security context with user and group permissions only
val owner = UserContext("lupita", "finance")
val docs  = DocumentStore(owner.userId, owner.groupId)

// Set security context to owner
given SecurityContext = owner

// Owner can read and write to document store
docs.put("meeting-agenda.txt", "Increase developers' salaries")
docs.get("meeting-agenda.txt")
```

### The Omnipotent Root Context

In the examples so far, we've used `UserContext`, which is a security context
with a finite set of granted permissions.

The other type of security context is `RootContext`, which has an infinite set
of granted permissions. Rather, there's no permission it doesn't have. It's the
_superuser_ security context.

`RootContext` is an object implementation, so there is only one instance of it.
It should be used for the purpose of effectively bypassing security checks.

```scala
// Print all messages
SecureMessages.list(using RootContext).foreach(println)

(0 to 999999).foreach { _ =>
  // Create permission with randomly generated name
  val perm = Permission(scala.util.Random.nextString(8))

  // Assert permission is granted
  assert(RootContext.test(perm))
}
```

The following script is a more intricate example. It demonstrates how to
simulate _sudo_ functionality. It does this by defining a group permission to
regulate user access to `RootContext`.

```scala
import little.security.*

object sudo:
  // Define group permission required for sudo
  private val sudoers = GroupPermission("sudoers")

  def apply[T](op: SecurityContext => T)(using security: SecurityContext): T =
    // Test permission before switching to root
    security(sudoers) { op(RootContext) }

object SecureMessages:
  private case class Message(text: String, permission: Permission)

  private val messages = Seq(
    Message("This is a public message."   , Permission("public")),
    Message("This is a protected message.", Permission("protected")),
    Message("This is a private message."  , Permission("private"))
  )

  def list(using security: SecurityContext): Seq[String] =
    messages.filter(msg => security.test(msg.permission)).map(_.text)

// Set security context
given SecurityContext = UserContext("losizm", "staff",
  Permission("public"),
  Permission("protected"),
  GroupPermission("sudoers") // Add group permission required for sudo
)

println("Print messages in user context...")
SecureMessages.list.foreach(println)

println("Print messages in sudo context...")
// NOTE: The `implicit security` below "shadows" the previously declared
// security context. The new context is provided by sudo.
sudo { implicit security =>
  SecureMessages.list.foreach(println)
}
```

## API Documentation

See [scaladoc](https://losizm.github.io/little-security/latest/api/little/security.html)
for additional details.

## License
**little-security** is licensed under the Apache License, Version 2. See [LICENSE](LICENSE)
for more information.
