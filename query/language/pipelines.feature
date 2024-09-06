# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

#noinspection CucumberUndefinedStep
Feature: TypeQL pipelines

  Background: Open connection and create a simple extensible schema
    Given typedb starts
    Given connection opens with default authentication
    Given connection has been opened
    Given connection does not have any database
    Given connection create database: typedb
    Given connection open schema transaction for database: typedb
    Given typeql define
      """
      define
      entity person owns ref @key,
        plays friendship:friend,
        plays employment:employee,
        owns name,
        owns age;
      entity company owns ref @key,
        plays employment:employer,
        owns name;
      relation friendship owns ref @key,
        relates friend;
      relation employment owns ref @key,
        relates employee,
        relates employer;
      attribute name value string;
      attribute age value long;
      attribute ref value long;
      """
    Given transaction commits


  Scenario: Matches can be chained, with variables bindings kept into later stages
    Given connection open write transaction for database: typedb
    Given typeql write query
    """
    insert
      $p1 isa person, has name "Alice", has age 10, has ref 0;
      $p2 isa person, has name "Bob", has age 11, has ref 1;
    """
    Given transaction commits

    Given connection open write transaction for database: typedb
    Given typeql read query
    """
    match
      $p isa person, has name $name;
    match
      $p has age $age;
    """
    Then uniquely identify answer concepts
      | p         | name            | age |
      | key:ref:0 | attr:name:Alice | 10  |
      | key:ref:1 | attr:name:Bob   | 11  |
