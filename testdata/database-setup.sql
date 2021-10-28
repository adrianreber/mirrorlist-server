DROP TABLE repository;
CREATE TABLE repository (
	id serial NOT NULL,
	prefix text NOT NULL,
	directory_id integer NOT NULL,
	category_id integer NOT NULL,
	arch_id integer NOT NULL,
	version_id integer NOT NULL,
	disabled boolean
);

DROP TABLE host_category;
CREATE TABLE host_category (
	id serial NOT NULL,
	host_id integer NOT NULL,
	category_id integer NOT NULL,
	always_up2date boolean
);

DROP TABLE host;
CREATE TABLE host (
	id serial NOT NULL,
	name text NOT NULL,
	site_id integer NOT NULL,
	user_active boolean,
	admin_active boolean,
	bandwidth_int integer NOT NULL,
	country text NOT NULL,
	asn_clients boolean,
	asn integer,
	max_connections integer,
	private boolean,
	internet2 boolean,
	internet2_clients boolean
);

DROP TABLE site;
CREATE TABLE site (
	id serial NOT NULL,
	user_active boolean,
	admin_active boolean,
	private boolean
);

DROP TABLE host_category_url;
CREATE TABLE host_category_url (
	id serial NOT NULL,
	host_category_id integer NOT NULL,
	url text NOT NULL,
	private boolean
);

DROP TABLE category;
CREATE TABLE category (
	id serial NOT NULL,
	topdir_id integer NOT NULL
);

DROP TABLE host_category_dir;
CREATE TABLE host_category_dir (
	id serial NOT NULL,
	host_category_id integer NOT NULL,
	path text NOT NULL,
	up2date boolean NOT NULL,
	directory_id integer NOT NULL
);

DROP TABLE file_detail;
CREATE TABLE file_detail (
	id serial NOT NULL,
	directory_id integer NOT NULL,
	filename text NOT NULL,
	"timestamp" bigint,
	size bigint,
	sha1 text,
	md5 text,
	sha256 text,
	sha512 text
);

DROP TABLE directory;
CREATE TABLE directory (
	id serial NOT NULL,
	name text NOT NULL,
	files bytea,
	readable boolean,
	ctime bigint
);

DROP TABLE category_directory;
CREATE TABLE category_directory (
	category_id integer NOT NULL,
	directory_id integer NOT NULL,
	ctime bigint
);

DROP TABLE version;
CREATE TABLE version (
	id serial NOT NULL,
	name text,
	product_id integer,
	is_test boolean,
	display boolean,
	display_name text,
	ordered_mirrorlist boolean,
	sortorder integer NOT NULL,
	codename text
);

DROP TABLE arch;
CREATE TABLE arch (
	id serial NOT NULL,
	name text
);
