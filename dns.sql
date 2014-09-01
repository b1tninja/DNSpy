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
CREATE TABLE IF NOT EXISTS `names` (
  `id` bigint(10) unsigned NOT NULL AUTO_INCREMENT,
  `parent` bigint(10) unsigned DEFAULT NULL,
  `name` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `parent` (`parent`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.


-- Dumping structure for table dns.queries
CREATE TABLE IF NOT EXISTS `queries` (
  `id` bigint(10) unsigned NOT NULL AUTO_INCREMENT,
  `question` bigint(10) unsigned NOT NULL DEFAULT '0',
  `nameserver` bigint(10) unsigned NOT NULL DEFAULT '0',
  `address` bigint(10) unsigned NOT NULL DEFAULT '0',
  `requested` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `question` (`question`),
  KEY `nameserver` (`nameserver`),
  KEY `address` (`address`),
  CONSTRAINT `address` FOREIGN KEY (`address`) REFERENCES `records` (`id`),
  CONSTRAINT `nameserver` FOREIGN KEY (`nameserver`) REFERENCES `records` (`id`),
  CONSTRAINT `question` FOREIGN KEY (`question`) REFERENCES `questions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.


-- Dumping structure for table dns.questions
CREATE TABLE IF NOT EXISTS `questions` (
  `id` bigint(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` bigint(10) unsigned NOT NULL,
  `type` smallint(5) unsigned NOT NULL,
  `class` smallint(5) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name_fk` (`name`),
  CONSTRAINT `name_fk` FOREIGN KEY (`name`) REFERENCES `names` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.


-- Dumping structure for table dns.records
CREATE TABLE IF NOT EXISTS `records` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` bigint(20) unsigned NOT NULL,
  `type` smallint(5) unsigned NOT NULL,
  `class` smallint(5) unsigned NOT NULL,
  `ttl` int(10) unsigned NOT NULL,
  `rdata` blob,
  `query` bigint(20) unsigned DEFAULT NULL,
  `cached` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `query` (`query`),
  KEY `name` (`name`),
  CONSTRAINT `name` FOREIGN KEY (`name`) REFERENCES `names` (`id`),
  CONSTRAINT `query` FOREIGN KEY (`query`) REFERENCES `queries` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Data exporting was unselected.
/*!40014 SET FOREIGN_KEY_CHECKS=1 */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;

