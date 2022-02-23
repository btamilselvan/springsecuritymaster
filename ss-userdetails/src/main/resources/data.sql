DROP TABLE IF EXISTS user;
 
CREATE TABLE user (
  id INT AUTO_INCREMENT  PRIMARY KEY,
  username VARCHAR(50),
  password VARCHAR(250)
);
 
INSERT INTO user (id, username, password) VALUES 
(1, 'user1', '$2a$10$.B1wFyO1BXj3.J5WTSDHxuamH2.7Qq/Q9Cop5.fLxSvGVPTj2JWPi');

INSERT INTO user (id, username, password) VALUES 
(2, 'user2', '$2a$10$TYdEAaNsxCpSMfvuRIWPyuWfuaqWvodR6uiuq7q.lL7/h.XAe95n6');
