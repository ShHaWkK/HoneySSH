# Using the Fake MySQL Shell

This honeypot includes a simulated MySQL monitor. You can enter it from the SSH shell by typing `mysql`.

Once inside, commands must end with `;` or `\g` just like a normal MySQL client.

## Supported commands

- `SHOW DATABASES;` – list available databases
- `USE <db>;` – switch the current database
- `SHOW TABLES;` – list tables in the selected database
- `DESCRIBE <table>;` – show columns of a table
- `SELECT <cols> FROM <table>;` – display rows from a table
- `INSERT INTO <table> VALUES (...);` – insert a row
- `UPDATE <table> SET <col>=<val> WHERE <cond>;` – update rows
- `DELETE FROM <table> WHERE <cond>;` – delete rows
- `exit`, `quit` or `\q` – leave the MySQL monitor

## Example scenario

```text
$ mysql
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1
Server version: 5.7.42 MySQL Community Server (fake)

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| employees          |
| archive            |
+--------------------+
2 rows in set (0.00 sec)

mysql> USE employees;
Database changed

mysql> SHOW TABLES;
+----------------------+
| Tables_in_employees  |
+----------------------+
| users                |
| logins               |
+----------------------+
2 rows in set (0.00 sec)

mysql> DESCRIBE users;
+-------+
| Field |
+-------+
| id    |
| name  |
+-------+
2 rows in set (0.00 sec)

mysql> INSERT INTO users VALUES (1, 'alice');
Query OK, 1 row affected (0.00 sec)

mysql> SELECT * FROM users;
+----+-------+
| id | name  |
+----+-------+
| 1  | alice |
+----+-------+
1 rows in set (0.00 sec)

mysql> DELETE FROM users WHERE id=1;
Query OK, 1 row affected (0.00 sec)

mysql> exit
Bye
```
