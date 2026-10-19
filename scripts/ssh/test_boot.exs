# Run SSH-scoped tests without starting unrelated umbrella applications.
# The caller supplies a disposable PostgreSQL database through PGHOST/PGPORT.
Logger.configure(level: :warning)
{:ok, _} = Application.ensure_all_started(:secrethub_core)
