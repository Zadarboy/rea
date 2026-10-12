import { userInfo } from "node:os";

/** An empty home variable selects nothing; joining onto it would target the working directory. */
const selected = (value: string | undefined): string | undefined =>
  value === "" ? undefined : value;

/** Resolve the caller's selected home before consulting the host account. */
export const homeDirectoryFromEnvironment = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
): string => {
  const home = selected(environment.HOME);
  const profile = selected(environment.USERPROFILE);
  const drive = selected(environment.HOMEDRIVE);
  const path = selected(environment.HOMEPATH);
  const choice =
    platform === "win32"
      ? (profile ??
        (drive !== undefined && path !== undefined ? `${drive}${path}` : home))
      : (home ?? profile);
  return choice ?? userInfo().homedir;
};
