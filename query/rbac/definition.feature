# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

#noinspection CucumberUndefinedStep
# TODO: redefining a role (adding accesses via a second `define rbac ...`) — merge or error?
# TODO: undefining a role that has been granted to users — block, cascade, or leave dangling grants?
# TODO: undefining the last access on a role — implicitly deletes the role or leaves an empty one?
# TODO: the enforcement scenarios below read/write attributes (e.g. `has text`) while only holding
#       access on the owning entity type, not the attribute type itself. This currently succeeds,
#       but it is undecided whether attribute types will require their own access in the future.
Feature: Defining RBAC roles

  Background:
    Given typedb starts
    Given connection opens with default authentication
    Given connection is open: true
    Given connection has 0 databases
    Given connection create database: typedb
    Given connection open schema transaction for database: typedb

    Given typeql schema query
    """
    define
      attribute email, value string;
      attribute text, value string;
      attribute views, value integer;

      relation authorship,
        relates content @card(1),
        relates author;


      entity post,
        owns text, owns views,
        plays authorship:content;
      entity comment,
        owns text, owns views,
        plays authorship:content;
      entity user,
        owns email,
        plays authorship:author;
    """
    Given transaction commits


  Scenario: RBAC roles can be defined & read back
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-readers,
        reads { post, comment, user },
        writes { views };
    """
    # Read them from the buffer
    Then list rbac declared access for role: post-readers
      | type    | access |
      | post    | read   |
      | comment | read   |
      | user    | read   |
      | views   | write  |
    Given transaction commits

    # Read them without a cache
    Given connection open schema transaction for database: typedb
    Then list rbac declared access for role: post-readers
      | type    | access |
      | post    | read   |
      | comment | read   |
      | user    | read   |
      | views   | write  |
    Given transaction closes
    # Read them from a cache
    Given connection open read transaction for database: typedb
    Then list rbac declared access for role: post-readers
      | type    | access |
      | post    | read   |
      | comment | read   |
      | user    | read   |
      | views   | write  |

    Then rbac role 'post-readers' has read access on type 'post': true
    Then rbac role 'post-readers' has read access on type 'comment': true
    Then rbac role 'post-readers' has read access on type 'user': true
    # Write access implies read access?
    # Then rbac role 'post-readers' has read access on type 'views': true

    Then rbac role 'post-readers' has write access on type 'post': false
    Then rbac role 'post-readers' has write access on type 'comment': false
    Then rbac role 'post-readers' has write access on type 'user': false
    Then rbac role 'post-readers' has write access on type 'views': true


  Scenario: Undefining an RBAC role removes it
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-readers,
        reads { post, comment },
        writes { views };
    """
    Given transaction commits

    Given connection open schema transaction for database: typedb
    Then rbac role 'post-readers' exists: true
    When typeql schema query
    """
    undefine
      rbac post-readers;
    """
    Then rbac role 'post-readers' exists: false
    Given transaction commits

    Given connection open schema transaction for database: typedb
    Then rbac role 'post-readers' exists: false
    Given transaction closes

    Given connection open read transaction for database: typedb
    Then rbac role 'post-readers' exists: false


  Scenario: Undefining a specific access on an RBAC role leaves the role and other accesses intact
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-readers,
        reads { post, comment },
        writes { views };
    """
    Given transaction commits

    Given connection open schema transaction for database: typedb
    When typeql schema query
    """
    undefine
      reads { post } from post-readers;
    """
    Then list rbac declared access for role: post-readers
      | type    | access |
      | comment | read   |
      | views   | write  |
    Given transaction commits

    Given connection open read transaction for database: typedb
    Then rbac role 'post-readers' exists: true
    Then list rbac declared access for role: post-readers
      | type    | access |
      | comment | read   |
      | views   | write  |


  # --- Enforcement: RBAC role access ---

  Scenario: A user with an RBAC read role can read types in the role but not types outside it
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-reader,
        reads { post, comment };
    """
    Given transaction commits

    Given connection open write transaction for database: typedb
    Given typeql write query
    """
    insert $p isa post, has text "hello world";
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-read', password 'mypassword'
    Given grant user 'user-enf-rbac-read' database role: typedb:post-reader
    Given connection closes

    Given connection opens with username 'user-enf-rbac-read', password 'mypassword'
    Given connection open read transaction for database: typedb
    When get answers of typeql read query
    """
    match $p isa post;
    """
    Then answer size is: 1
    Then typeql read query; fails with a message containing: "TODO: access to type 'user' denied"
    """
    match $u isa user;
    """
    Given connection closes


  Scenario: A user with an RBAC read-only role cannot write to types in that role
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-reader,
        reads { post };
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-read-only', password 'mypassword'
    Given grant user 'user-enf-rbac-read-only' database role: typedb:post-reader
    Given connection closes

    Given connection opens with username 'user-enf-rbac-read-only', password 'mypassword'
    Given connection open write transaction for database: typedb
    Then typeql write query; fails with a message containing: "TODO: write access to type 'post' denied"
    """
    insert $p isa post, has text "unauthorized";
    """
    Given connection closes


  Scenario: A user with an RBAC write role can write to types in the role but not types outside it
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-writer,
        writes { post };
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-write', password 'mypassword'
    Given grant user 'user-enf-rbac-write' database role: typedb:post-writer
    Given connection closes

    Given connection opens with username 'user-enf-rbac-write', password 'mypassword'
    Given connection open write transaction for database: typedb
    When get answers of typeql write query
    """
    insert $p isa post, has text "allowed";
    """
    Then answer size is: 1
    Then transaction commits

    Given connection open write transaction for database: typedb
    Then typeql write query; fails with a message containing: "TODO: access to type 'comment' denied"
    """
    insert $c isa comment, has text "not allowed";
    """
    Given connection closes


  # --- Enforcement: RBAC role access inheritance ---

  Scenario: An RBAC read role is inherited by subtypes but does not propagate to supertypes
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      entity blog-post sub post;
      rbac post-reader,
        reads { post };
      rbac blog-post-reader,
        reads { blog-post };
    """
    Given transaction commits

    Given connection open write transaction for database: typedb
    Given typeql write query
    """
    insert $p isa blog-post, has text "inherited";
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-inherit-read-super', password 'mypassword'
    Given create user with username 'user-enf-rbac-inherit-read-sub', password 'mypassword'
    Given grant user 'user-enf-rbac-inherit-read-super' database role: typedb:post-reader
    Given grant user 'user-enf-rbac-inherit-read-sub' database role: typedb:blog-post-reader
    Given connection closes

    # The supertype role grants read access on the subtype
    Given connection opens with username 'user-enf-rbac-inherit-read-super', password 'mypassword'
    Given connection open read transaction for database: typedb
    When get answers of typeql read query
    """
    match $p isa blog-post;
    """
    Then answer size is: 1
    Given connection closes

    # The subtype role does not grant read access on the supertype
    Given connection opens with username 'user-enf-rbac-inherit-read-sub', password 'mypassword'
    Given connection open read transaction for database: typedb
    Then typeql read query; fails with a message containing: "TODO: access to type 'post' denied"
    """
    match $p isa post;
    """
    Given connection closes


  Scenario: An RBAC write role is inherited by subtypes but does not propagate to supertypes
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      entity blog-post sub post;
      rbac post-writer,
        writes { post };
      rbac blog-post-writer,
        writes { blog-post };
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-inherit-write-super', password 'mypassword'
    Given create user with username 'user-enf-rbac-inherit-write-sub', password 'mypassword'
    Given grant user 'user-enf-rbac-inherit-write-super' database role: typedb:post-writer
    Given grant user 'user-enf-rbac-inherit-write-sub' database role: typedb:blog-post-writer
    Given connection closes

    # The supertype role grants write access on the subtype
    Given connection opens with username 'user-enf-rbac-inherit-write-super', password 'mypassword'
    Given connection open write transaction for database: typedb
    When get answers of typeql write query
    """
    insert $p isa blog-post, has text "inherited";
    """
    Then answer size is: 1
    Then transaction commits
    Given connection closes

    # The subtype role does not grant write access on the supertype
    Given connection opens with username 'user-enf-rbac-inherit-write-sub', password 'mypassword'
    Given connection open write transaction for database: typedb
    Then typeql write query; fails with a message containing: "TODO: write access to type 'post' denied"
    """
    insert $p isa post, has text "not allowed";
    """
    Given connection closes


  # --- Enforcement: multiple RBAC roles ---

  Scenario: A user granted multiple RBAC roles has the union of their accesses
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-writer,
        writes { post };
      rbac comment-reader,
        reads { comment };
    """
    Given transaction commits

    Given connection open write transaction for database: typedb
    Given typeql write query
    """
    insert $c isa comment, has text "existing comment";
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-multi', password 'mypassword'
    Given grant user 'user-enf-rbac-multi' database role: typedb:post-writer
    Given grant user 'user-enf-rbac-multi' database role: typedb:comment-reader
    Given connection closes

    Given connection opens with username 'user-enf-rbac-multi', password 'mypassword'

    # comment-reader grants read access on comment
    Given connection open read transaction for database: typedb
    When get answers of typeql read query
    """
    match $c isa comment;
    """
    Then answer size is: 1
    # but neither role grants read access on user
    Then typeql read query; fails with a message containing: "TODO: access to type 'user' denied"
    """
    match $u isa user;
    """
    Given transaction closes

    # post-writer grants write access on post
    Given connection open write transaction for database: typedb
    When get answers of typeql write query
    """
    insert $p isa post, has text "allowed";
    """
    Then answer size is: 1
    Then transaction commits

    # but neither role grants write access on comment (comment is read-only here)
    Given connection open write transaction for database: typedb
    Then typeql write query; fails with a message containing: "TODO: write access to type 'comment' denied"
    """
    insert $c isa comment, has text "not allowed";
    """
    Given connection closes


  # NOTE: provisional behaviour — whether write access implies read access is not yet finalised.
  Scenario: An RBAC write role also grants read access on the same type
    Given connection open schema transaction for database: typedb
    Given typeql schema query
    """
    define
      rbac post-writer,
        writes { post };
    """
    Given transaction commits

    Given create user with username 'user-enf-rbac-write-implies-read', password 'mypassword'
    Given grant user 'user-enf-rbac-write-implies-read' database role: typedb:post-writer
    Given connection closes

    Given connection opens with username 'user-enf-rbac-write-implies-read', password 'mypassword'
    Given connection open write transaction for database: typedb
    Given typeql write query
    """
    insert $p isa post, has text "written";
    """
    Then transaction commits

    Given connection open read transaction for database: typedb
    When get answers of typeql read query
    """
    match $p isa post;
    """
    Then answer size is: 1
    Given connection closes

