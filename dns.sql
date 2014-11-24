/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET FOREIGN_KEY_CHECKS=0 */;


-- Dumping structure for table dns.blob
CREATE TABLE IF NOT EXISTS `blob` (
  `sha1` binary(20) NOT NULL,
  `blob` blob NOT NULL,
  PRIMARY KEY (`sha1`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;


-- Dumping structure for table dns.blacklist
CREATE TABLE IF NOT EXISTS `blacklist` (
  `ip` VARBINARY(16) NOT NULL,
--  `reason` TINYINT(3) UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`ip`),
  CONSTRAINT `blacklist_ip_fk` FOREIGN KEY (`ip`) REFERENCES `blob` (`sha1`)
) ENGINE=InnoDB;


-- Dumping structure for table dns.packet
CREATE TABLE IF NOT EXISTS `packet` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `source` varbinary(16) NULL,
  `source_port` smallint(6) unsigned NOT NULL DEFAULT 0,
  `destination` varbinary(16) NULL,
  `destination_port` smallint(6) unsigned NOT NULL DEFAULT 53,
  `txnid` int(10) unsigned NOT NULL,
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
  `queryset` binary(20) NOT NULL,
  `recordset` binary(20) NOT NULL,
  `cached` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `source` (`source`),
  KEY `destination` (`destination`),
  KEY `queryset` (`queryset`),
  KEY `recordset` (`recordset`)
) ENGINE=InnoDB;


-- Dumping structure for table dns.names
CREATE TABLE IF NOT EXISTS `name` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `parent` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `parent` (`parent`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_general_ci;


-- Dumping structure for table dns.question
CREATE TABLE IF NOT EXISTS `question` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` bigint(20) unsigned NOT NULL,
  `qtype` smallint(5) unsigned NOT NULL,
  `qclass` smallint(5) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  CONSTRAINT `question_name_fk` FOREIGN KEY (`name`) REFERENCES `name` (`id`)
) ENGINE=InnoDB;


-- TODO: consider folding name,rtype,rclass into "question" table, may help with deduplication/search later on...
-- especially in the event of lots of rtypes,rclass,rdata pairs under one name
-- Dumping structure for table dns.record
CREATE TABLE IF NOT EXISTS `record` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` bigint(20) unsigned NOT NULL,
  `rtype` smallint(5) unsigned NOT NULL,
  `rclass` smallint(5) unsigned NOT NULL,
  `rdata` binary(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `rdata` (`rdata`),
  CONSTRAINT `record_name_fk` FOREIGN KEY (`name`) REFERENCES `name` (`id`),
  CONSTRAINT `record_rdata_fk` FOREIGN KEY (`rdata`) REFERENCES `blob` (`sha1`)
) ENGINE=InnoDB;

-- Dumping structure for table dns.packet_question
CREATE TABLE IF NOT EXISTS `packet_question` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT, -- shouldn't/can't depend on INSERT default SORT BY order...
  `packet` bigint(20) unsigned NOT NULL,
  `question` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `packet` (`packet`),
  KEY `question` (`question`),
  CONSTRAINT `packet_question_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`id`),
  CONSTRAINT `packet_question_question_fk` FOREIGN KEY (`question`) REFERENCES `question` (`id`)
) ENGINE=InnoDB;


-- Dumping structure for table dns.query
CREATE TABLE IF NOT EXISTS `query` (
  `packet` bigint(20) unsigned NOT NULL,
  `parent` bigint(20) unsigned NULL,
  `nameserver` bigint(20) unsigned NULL,
  `address` bigint(20) unsigned NULL,
-- TODO: consider "multiple response" case, as well as TC
  `response` bigint(20) unsigned NULL,
  PRIMARY KEY (`packet`),
  KEY `parent` (`parent`),
  KEY `nameserver` (`nameserver`),
  KEY `address` (`address`),
  KEY `response` (`response`),
--  CONSTRAINT `query_parent_fk` FOREIGN KEY (`parent`) REFERENCES `query` (`id`),
  CONSTRAINT `query_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`id`),
  CONSTRAINT `query_nameserver_fk` FOREIGN KEY (`nameserver`) REFERENCES `record` (`id`),
  CONSTRAINT `query_address_fk` FOREIGN KEY (`address`) REFERENCES `record` (`id`),
  CONSTRAINT `query_response_fk` FOREIGN KEY (`response`) REFERENCES `packet` (`id`)
) ENGINE=InnoDB;


-- Dumping structure for table dns.packet_record
CREATE TABLE IF NOT EXISTS `packet_record` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT, -- shouldn't/can't depend on INSERT default SORT BY order...
  `packet` bigint(20) unsigned NOT NULL,
  `record` bigint(20) unsigned NOT NULL,
  -- TODO: Might be nice to have a field for the over-the-wire bytes of a given name
  -- TODO: RFC2181 suggests ttl be "ignored" when considering record sets, log as part of the packet instead of the record
  `ttl` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `packet` (`packet`),
  KEY `record` (`record`),
  CONSTRAINT `packet_record_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`id`),
  CONSTRAINT `packet_record_record_fk` FOREIGN KEY (`record`) REFERENCES `record` (`id`)
) ENGINE=InnoDB;


/*!40014 SET FOREIGN_KEY_CHECKS=1 */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;

