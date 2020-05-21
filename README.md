# little-security

The Scala library that adds a little security to applications.

[![Maven Central](https://img.shields.io/maven-central/v/com.github.losizm/little-security_2.13.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.github.losizm%22%20AND%20a:%22little-security.12%22)

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
  - [The Omnipotent Root Security](#The-Omnipotent-Root-Security)
- [API Documentation](#API-Documentation)
- [License](#License)


## Getting Started
To use **little-security**, add it to your library dependencies.

```scala
libraryDependencies += "com.github.losizm" %% "little-security" % "0.2.0"
```

## How It Works

**little-security** is powered by a pair of traits: `Permission` and
`SecurityContext`.

A `Permission` is defined with a given name, and one or more permissions can be
applied to a restricted operation.

A `SecurityContext` establishes a pattern in which a restricted operation is
performed only if its required permissions are granted. Otherwise, a
`SecurityViolation` is raised.

### Security in Action

The following script demonstrates how read/write access to an in-memory cache
could be implemented. We won't discuss any of its details: It's provided merely
to highlight a simple use case. See inline comments for notable bits of code.

```scala
import little.security.{ Permission, SecurityContext, UserSecurity }

import scala.collection.concurrent.TrieMap

object SecureCache {
  // Define permissions for reading and writing cache entries
  private val getPermission = Permission("cache:get")
  private val setPermission = Permission("cache:set")

  private val cache = TrieMap[String, String](
    "gang starr"      -> "step in the arena",
    "digable planets" -> "blowout comb"
  )

  def get(key: String)(implicit security: SecurityContext): String =
    // Tests for read permission before getting cache entry
    security(getPermission) { () =>
      cache(key)
    }

  def set(key: String, value: String)(implicit security: SecurityContext): Unit =
    // Tests for write permission before setting cache entry
    security(setPermission) { () =>
      cache += key -> value
    }
}

// Create security context for user with read permission to cache
implicit val user = UserSecurity("losizm", "staff", Permission("cache:get"))

// Get cache entry
val value = SecureCache.get("gang starr")

// Throw SecurityViolation because user lacks write permission
SecureCache.set("sucker mc", value)
```

## Permission

A `Permission` is identified by its name, and you're free to implement any
convention for the names used in your application.

The following defines 3 permissions, any of which could be used as a
permission for read access to an archive module.

```scala
val perm1 = Permission("archive:read")
val perm2 = Permission("module=archive; access=read")
val perm3 = Permission("[[read]] /api/modules/archive")
```

### User and Group Permissions

A user permission is created with `UserPermission`. There's no implementing
class: It's just a factory. It constructs a permission with a specially
formatted name using user and group identiers.

```scala
val userPermission = UserPermission("losizm", "staff")

// Destructure permission to its user and group identifiers
userPermission match {
  case UserPermission(uid, gid) => println(s"userId=$uid, groupId=$gid")
}
```

And `GroupPermission` constructs a permission with a specially formatted name
using a group identifier only.

```scala
val groupPermission = GroupPermission("staff")

// Destructure permission to its group identifier
groupPermission match {
  case GroupPermission(gid) => println(s"groupId=$gid")
}
```

See also [Automatic User and Group Permissions](#Automatic-User-and-Group-Permissions).

## Security Context

A `SecurityContext` is consulted for permission to apply a restricted operation.
If permission is granted, the operation is applied; otherwise, the security
context raises a `SecurityViolation`.

`UserSecurity` is an implementation of a security context. It is constructed
with supplied user and group identifiers along with a set of granted
permissions.

```scala
import little.security.{ Permission, SecurityContext, UserSecurity }

object BuildManager {
  private val buildPermission      = Permission("action=build")
  private val deployDevPermission  = Permission("action=deploy; env=dev")
  private val deployProdPermission = Permission("action=deploy; env=prod")

  def build(project: String)(implicit security: SecurityContext): Unit =
    // Check permission before performing action
    security(buildPermission) { () =>
      println(s"Build $project.")
    }

  def deployToDev(project: String)(implicit security: SecurityContext): Unit =
    // Check permission before performing action
    security(deployDevPermission) { () =>
      println(s"Deploy $project to dev environment.")
    }

  def deployToProd(project: String)(implicit security: SecurityContext): Unit =
    // Check permission before performing action
    security(deployProdPermission) { () =>
      println(s"Deploy $project to prod environment.")
    }
}

// Create user security with two permissions
implicit val user = UserSecurity("ishmael", "developer",
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

`SecurityContext.any(Permission*)` is used to ensure that at least one of the
supplied permissions is granted before an operation is applied.

`SecurityContext.all(Permission*)` is used to ensure that all supplied
permissions are granted before an operation is applied.

```scala
import little.security.{ Permission, SecurityContext, UserSecurity }

object FileManager {
  private val readOnlyPermission  = Permission("file:read-only")
  private val readWritePermission = Permission("file:read-write")
  private val encryptPermission   = Permission("file:encrypt")

  def read(fileName: String)(implicit security: SecurityContext): Unit =
    // Get either read-only or read-write permission before performing operation
    security.any(readOnlyPermission, readWritePermission) { () =>
      println(s"Read $fileName.")
    }

  def encrypt(fileName: String)(implicit security: SecurityContext): Unit =
    // Get both read-write and encrypt permissions before performing operation
    security.all(readWritePermission, encryptPermission) { () =>
      println(s"Encrypt $fileName.")
    }
}

implicit val user = UserSecurity("isaac", "ops", Permission("file:read-write"))

// Can read via read-write permission
FileManager.read("/etc/passwd")

// Has read-write but lacks encrypt permission -- throw SecurityViolation
FileManager.encrypt("/etc/passwd")
```

### Testing Permissions

Sometimes, it may be enough to simply check a permission to see whether it is
granted, and not necessarily throw a `SecurityViolation` if it isn't. That's
precisely what `SecurityContext.test(Permission)` is for. It returns `true` or
`false` based on the permission being granted or not. It's an ideal predicate to
a security filter, as demonstrated in the following script.

```scala
import little.security.{ Permission, SecurityContext, UserSecurity }

object SecureMessages {
  // Define class for text message with assigned permission
  private case class Message(text: String, permission: Permission)

  private val messages = Seq(
    Message("This is public message #1."   , Permission("public")),
    Message("This is public message #2."   , Permission("public")),
    Message("This is private message #1."  , Permission("private")),
    Message("This is public message #3."   , Permission("public")),
    Message("This is protected message #1.", Permission("protected"))
  )

  def list(implicit security: SecurityContext): Seq[String] =
    // Filter messages by testing permission
    messages.filter(msg => security.test(msg.permission))
      .map(_.text)
}

// Create user with "public" and "protected" permissions
implicit val user = UserSecurity("losizm", "staff",
  Permission("public"),
  Permission("protected")
)

// Print all accessible messages
SecureMessages.list.foreach(println)
```

### Automatic User and Group Permissions

When an instance of `UserSecurity` is created, user and group permissions are
added to the permissions expressly supplied in constructor.

```scala
val user = UserSecurity("losizm", "staff", Permission("read"))

assert(user.test(Permission("read")))
assert(user.test(UserPermission("losizm", "staff")))
assert(user.test(GroupPermission("staff")))
```

You're not required to make use of these permissions. However, they are added as
convenience for possible use cases such as document sharing.

For example, if a user owns a document, she should have read/write access to
that document. And, if it's shared, then read-only access could be given to her
group.

```scala
import little.security._

import scala.collection.concurrent.TrieMap

class DocumentStore(userId: String, groupId: String) {
  private case class Document(text: String, permission: Permission)

  private val userPermission  = UserPermission(userId, groupId)
  private val groupPermission = GroupPermission(groupId)

  private val storage = new TrieMap[String, Document]

  def get(name: String)(implicit security: SecurityContext): String =
    storage.get(name).map { doc =>
      // If shared, then the user and anyone in her group can read it
      // If not shared, then only the user can read it
      security(doc.permission) { () => doc.text }
    }.get

  def put(name: String, text: String, shared: Boolean)
      (implicit security: SecurityContext): Unit =
    // Only the user can write to her document store
    security(userPermission) { () =>
      shared match {
        // If shared, store with group permission
        case true  => storage += name -> Document(text, groupPermission)

        // If not shared, store with user permission
        case false => storage += name -> Document(text, userPermission)
      }
    }
}

// Create security context with user and group permissions only
implicit val user = UserSecurity("lupita", "finance")

val docs = new DocumentStore(user.userId, user.groupId)

// Owner can always read and write to document store
docs.put("meeting-agenda.txt", "Be on time.", true)
docs.get("meeting-agenda.txt")
docs.put("pto.txt", "2020-03-01 - On holiday", false)
docs.get("pto.txt")
```

### The Omnipotent Root Security

In the examples so far, we've used `UserSecurity`, which is a security context
with a finite set of granted permissions.

The other type of security context is `RootSecurity`, which has an infinite set
of granted permissions. That is, there's no permission it doesn't have. It's the
_superuser_ security context.

`RootSecurity` is an object implementation, so there's only one instance of it.
It should be used for the purpose of effectively bypassing security checks.

```scala
// Print all messages
SecureMessages.list(RootSecurity).foreach(println)

(0 to 999999).foreach { _ =>
  // Create permission with randomly generated name
  val perm = Permission(scala.util.Random.nextString(8))

  // Assert permission is granted
  assert(RootSecurity.test(perm))
}
```

## API Documentation

See [scaladoc](https://losizm.github.io/little-security/latest/api/little/security/index.html)
for additional details.

## License
**little-security** is licensed under the Apache License, Version 2. See [LICENSE](LICENSE)
for more information.
