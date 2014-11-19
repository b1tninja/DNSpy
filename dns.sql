-- --------------------------------------------------------
-- Host:                         127.0.0.1
-- Server version:               5.3.12-MariaDB - mariadb.org binary distribution
-- Server OS:                    Win64
-- HeidiSQL version:             7.0.0.4053
-- Date/time:                    2014-02-02 02:04:50
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET FOREIGN_KEY_CHECKS=0 */;

-- Dumping structure for table dns.names
CREATE TABLE IF NOT EXISTS `name` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `parent` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(64) NOT NULL,
  PRIMARY KEY (`pk`),
  KEY `parent` (`parent`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.


-- Dumping structure for table dns.query
CREATE TABLE IF NOT EXISTS `query` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `question` bigint(20) unsigned NOT NULL DEFAULT '0',
  `nameserver` bigint(20) unsigned NOT NULL DEFAULT '0',
  `address` bigint(20) unsigned NOT NULL DEFAULT '0',
  `requested` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`pk`),
  KEY `question` (`question`),
  KEY `nameserver` (`nameserver`),
  KEY `address` (`address`),
  CONSTRAINT `query_address_fk` FOREIGN KEY (`address`) REFERENCES `record` (`pk`),
  CONSTRAINT `query_nameserver_fk` FOREIGN KEY (`nameserver`) REFERENCES `record` (`pk`),
  CONSTRAINT `query_question_fk` FOREIGN KEY (`question`) REFERENCES `question` (`pk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.


-- Dumping structure for table dns.question
CREATE TABLE IF NOT EXISTS `question` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` bigint(20) unsigned NOT NULL,
  `qtype` smallint(5) unsigned NOT NULL,
  `qclass` smallint(5) unsigned NOT NULL,
  PRIMARY KEY (`pk`),
  KEY `name` (`name`),
  CONSTRAINT `question_name_fk` FOREIGN KEY (`name`) REFERENCES `name` (`pk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.


-- Dumping structure for table dns.record
CREATE TABLE IF NOT EXISTS `record` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` bigint(20) unsigned NOT NULL,
  `rtype` smallint(5) unsigned NOT NULL,
  `rclass` smallint(5) unsigned NOT NULL,
  `ttl` int(10) unsigned NOT NULL,
  `rdata` blob,
  `packet` bigint(20) unsigned NULL,
  `section` ENUM('qd','an','ns','ar') NOT NULL,
  `cached` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`pk`),
  KEY `name_idx` (`name`),
  KEY `packet_idx` (`packet`),
  CONSTRAINT `record_name_fk` FOREIGN KEY (`name`) REFERENCES `name` (`pk`),
  CONSTRAINT `record_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`pk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- Dumping structure for table dns.source_address
CREATE TABLE IF NOT EXISTS `source_address` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `type` ENUM('4','6') NOT NULL,
  `ip` VARCHAR(45) NOT NULL,
  `blacklisted` BIT(1) NOT NULL DEFAULT FALSE,
  PRIMARY KEY (`pk`),
  INDEX `ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.

-- Dumping structure for table dns.packet
CREATE TABLE IF NOT EXISTS `packet` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `source_address` bigint(20) unsigned NULL,
  `source_port` smallint(6) unsigned NOT NULL DEFAULT 0,
  `id` int(10) unsigned NOT NULL,
  `qr` bit(1),
  `opcode` bit(4),
  `aa` bit(1),
  `tc` bit(1),
  `rd` bit(1),
  `z` bit(3),
  `rcode` bit(4),
  `qdcount` smallint(6) unsigned NOT NULL,
  `ancount` smallint(6) unsigned NOT NULL,
  `nscount` smallint(6) unsigned NOT NULL,
  `arcount` smallint(6) unsigned NOT NULL,
  `cached` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`pk`),
  KEY `source_address` (`source_address`),
  CONSTRAINT `packet_source_address_fk` FOREIGN KEY (`source_address`) REFERENCES `source_address` (`pk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.

-- Dumping structure for table dns.response
CREATE TABLE IF NOT EXISTS `response` (
  `pk` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `query` bigint(20) unsigned NOT NULL,
  `packet` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`pk`),
  KEY `query` (`query`),
  KEY `packet` (`packet`),
  CONSTRAINT `response_query_fk` FOREIGN KEY (`query`) REFERENCES `query` (`pk`),
  CONSTRAINT `response_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`pk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.
/*!40014 SET FOREIGN_KEY_CHECKS=1 */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;

