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

    # Wait for PostgreSQL to be ready
    for i in $(seq 1 30); do
        if podman exec "${CONTAINER_NAME}" pg_isready -U postgres 2>/dev/null; then
            break
        fi
        sleep 1
    done

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
