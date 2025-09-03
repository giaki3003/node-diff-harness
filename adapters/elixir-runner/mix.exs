defmodule ElixirRunner.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_runner,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript_config()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :rocksdb]
    ]
  end

  defp deps do
    [
      # Elixir node implementation
      {:ama, path: "../../node/ex"},
      
      # JSON for trace parsing
      {:jason, "~> 1.4"},
      
      # VanillaSer validation NIF for consistency with Rust implementation
      {:rustler, "~> 0.36.2"},
      
      # Note: ETF serialization uses built-in :erlang.term_to_binary
      # Note: Using SHA256 for deterministic hashing (built-in :crypto module)
      
      # Development dependencies
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev], runtime: false}
    ]
  end

  defp escript_config do
    [
      main_module: ElixirRunner.CLI,
      name: "elixir_runner",
      embed_elixir: true,
      erl_opts: ["+fnu", "+pc", "unicode"]
    ]
  end
end