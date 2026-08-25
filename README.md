# Core Modules

**Rhinestone core modules for smart accounts**

Modules:

- **AutoSavings**: Automatically save a portion of received tokens into a vault
- **ColdStorageHook**: Secure your account by transforming it into cold storage for your assets
- **ColdStorageFlashloan**: Enable using the utility of your assets in cold storage through flashloans
- **DeadmanSwitch**: Secure your account by setting up a deadman switch
- **HookMultiPlexer**: Use multiple hooks based on granular conditions
- **MultiFactor**: Multiplex different validators to make your account more secure
- **OwnableExecutor**: Control your account from another account
- **OwnableValidator**: Own your account using an EOA or a set of EOAs
- **RegistryHook**: Use the Rhinestone Registry to ensure you only install secure modules
- **ScheduledOrders**: Automate swaps on a schedule
- **ScheduledTransfers**: Automate transfers on a schedule
- **SocialRecovery**: Recover your account using a set of trusted friends

## Using the modules

To use the modules in an application, head to our [sdk documentation](https://docs.rhinestone.dev/home/introduction/welcome-to-rhinestone) for more information.

## Using this repo

To install the dependencies, run:

```bash
pnpm install
```

To build the project, run:

```bash
forge build
```

To run the tests, run:

```bash
forge test
```

## Contributing

For feature or change requests, feel free to open a PR, start a discussion or get in touch with us.
