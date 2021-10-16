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
