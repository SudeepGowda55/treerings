# How AI was used to build Tree Rings

Tree Rings is built by team Matcrypt with an AI coding agent, Claude Code, doing most of the hands-on work under our direction. This file records the workflow, what the agent produced and what the humans decided. It is updated as the build goes on.

## Workflow

- **Research and idea selection.** The agent read the hackathon rules and prizes, surveyed the 153 projects already entered, read the QoreChain rollup documentation, and checked the live CT log list and the testnet's rollup module before the idea was chosen.
- **Building.** The agent writes the code, tests and documentation in small commits; every change is run against the real CT logs and the real QoreChain testnet before it is committed.
- **Review.** A second model reviews the plan at key points (for example, it caught that the rollup should not be created before the fraud-challenge rules were checked).

## Human contribution

- Sudeep chose to enter this hackathon, set the standing rules the agent follows (real data only, small commits, no placeholders), and made the account-level actions only a person can do (registrations, CAPTCHAs, passwords).
- Manvith joins as the second team member.

## Generated work

Listed per component as it lands.
