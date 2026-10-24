import { run } from "./main";

process.exitCode = await run(process.argv.slice(2));
