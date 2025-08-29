# Configuration for fuzzing mode - ensures clean stdout for binary protocol
import Config

# Suppress all logging to prevent stdout pollution
config :logger,
  level: :error,
  handle_otp_reports: false,
  handle_sasl_reports: false

# Force all logging to stderr, never stdout  
config :logger, :console,
  device: :standard_error,
  format: "[$level] $message\n",
  level: :error

# Disable any other loggers that might write to stdout
config :elixir, :ansi_enabled, false