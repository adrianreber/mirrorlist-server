#!/usr/bin/env bats

CONTAINER_NAME="mirrorlist-test-postgres"
POSTGRES_PASSWORD="test_password"
DB_NAME="test_db"
DB_PORT=5432

setup_file() {
    # Start PostgreSQL container
    podman run --detach \
        --name "${CONTAINER_NAME}" \
        --env POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
        --publish "${DB_PORT}:5432" \
        registry.access.redhat.com/hi/postgresql:latest

    # Wait for PostgreSQL to be ready.
    #
    # Ask over TCP and not over the unix socket. While initializing the
    # database the entrypoint starts a temporary server with
    # listen_addresses='' on the same socket and stops it again before
    # starting the real one, so a check on the socket can succeed on a
    # server which is about to go away. The temporary server cannot answer
    # on TCP, which makes this wait for the real one.
    for _ in $(seq 1 60); do
        if podman exec "${CONTAINER_NAME}" \
            pg_isready -h localhost -U postgres 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if ! podman exec "${CONTAINER_NAME}" pg_isready -h localhost -U postgres; then
        echo "PostgreSQL did not come up" >&2
        podman logs "${CONTAINER_NAME}" >&2
        return 1
    fi

    # Create database and load schema
    podman exec "${CONTAINER_NAME}" createdb -U postgres "${DB_NAME}"
    podman exec -i "${CONTAINER_NAME}" psql -U postgres -d "${DB_NAME}" \
        < testdata/database-setup.sql
}

teardown_file() {
    podman rm -f "${CONTAINER_NAME}" || true
}

@test "cargo build" {
    cargo build --verbose
}

@test "cargo clippy" {
    cargo clippy --all-targets --verbose -- -D warnings
}

@test "cargo fmt check" {
    cargo fmt --check
}

@test "cargo test" {
    TEST_DATABASE_URL="postgresql://postgres:${POSTGRES_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}" \
        cargo test --verbose -- --test-threads=1
}
