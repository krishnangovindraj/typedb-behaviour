# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

#noinspection CucumberUndefinedStep
Feature: Assigning permissions & RBAC roles

  Background:
    Given typedb starts
    Given connection opens with default authentication
    Given connection is open: true
    Given connection has 0 databases
    Given connection create database: typedb


  Scenario Outline: Users can be assigned the global '<has-permission>' permission
    Given create user with username '<user>', password 'mypassword'

    When grant user '<user>' permission: <has-permission>
    Then user '<user>' has permission: <has-permission>
    Then user '<user>' does not have permission: <doesnt-have-1>
    Then user '<user>' does not have permission: <doesnt-have-2>

    Examples:
      | user       | has-permission    | doesnt-have-1    | doesnt-have-2     |
      | user-gp-mu | manage-users      | manage-databases | grant-permissions |
      | user-gp-md | manage-databases  | manage-users     | grant-permissions |
      | user-gp-gp | grant-permissions | manage-users     | manage-databases  |

  Scenario Outline: Users can be assigned the '<permission>' permission on a specific database
    Given connection create database: mydb

    Given create user with username '<user>', password 'mypassword'
    When grant user '<user>' permission: <permission>:<database>
    Then user '<user>' has permission: <permission>:<database>
    Then user '<user>' <may-have-other> permission: <other-permission>:<database>

    Examples:
      | user          | database | permission        | may-have-other | other-permission  |
      | user-dp-tr-tw | mydb     | transaction-read  | does not have  | transaction-write |
      | user-dp-tr-st | mydb     | transaction-read  | does not have  | schema-types      |
      | user-dp-tr-sr | mydb     | transaction-read  | does not have  | schema-roles      |

      | user-dp-tw-tr | mydb     | transaction-write | does not have  | transaction-read  |
      | user-dp-tw-st | mydb     | transaction-write | does not have  | schema-types      |
      | user-dp-tw-sr | mydb     | transaction-write | does not have  | schema-roles      |

      | user-dp-st-tr | mydb     | schema-types      | does not have  | transaction-read  |
      | user-dp-st-tw | mydb     | schema-types      | does not have  | transaction-write |
      | user-dp-st-sr | mydb     | schema-types      | does not have  | schema-roles      |

      | user-dp-sr-tr | mydb     | schema-roles      | does not have  | transaction-read  |
      | user-dp-sr-tw | mydb     | schema-roles      | does not have  | transaction-write |
      | user-dp-sr-st | mydb     | schema-roles      | does not have  | schema-types      |

#
#  Scenario: Users can be assigned rbac roles from specific databases
#    Given connection create database: mydb
#
#    Given connection open schema transaction for database: mydb
#
#    Given typeql schema query
#    """
#    define
#      attribute email, value string;
#      attribute text, value string;
#      attribute views, value integer;
#
#      relation authorship,
#        relates content @card(1),
#        relates author;
#
#
#      entity post,
#        owns text, owns views,
#        plays authorship:content;
#      entity comment,
#        owns text, owns views,
#        plays authorship:content;
#      entity user,
#        owns email,
#        plays authorship:author;
#    """
#    Given typeql schema query
#    """
#    define
#      rbac post-readers,
#        reads { post, comment, user },
#        writes { views };
#    """
#    Given transaction commits
#
#    Given create user with username 'myuser', password 'mypassword'
#    When grant user 'myuser' database role: mydb:post-readers
#    Then user 'myuser' has database role: mydb:post-readers
