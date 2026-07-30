import { basename, join, resolve } from "path";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "fs";
import { CONVERTED_DIR, env, log, type ConvertedEntry } from "./lib";

const TOOL_DIR = resolve("media", ".garmin-mtp");
const HELPER_PATH = join(TOOL_DIR, "podrush-garmin-mtp");
const HELPER_SOURCE = resolve("native", "garmin-mtp.c");
const DOWNLOAD_DIR = join(TOOL_DIR, "downloads");
const SOURCE_DIR = join(TOOL_DIR, "sources");
const RUNTIME_DIR = join(TOOL_DIR, "runtime");
const MARKER_PATH = join(TOOL_DIR, "build.json");
const BUILD_TIMEOUT_MS = 5 * 60 * 1000;
const USB_TIMEOUT_MS = 12 * 60 * 1000;
const BUILD_REVISION = 1;

const DEPENDENCIES = {
  libusb: {
    version: "1.0.29",
    archive: "libusb-1.0.29.tar.bz2",
    url: "https://github.com/libusb/libusb/releases/download/v1.0.29/libusb-1.0.29.tar.bz2",
    sha256: "5977fc950f8d1395ccea9bd48c06b3f808fd3c2c961b44b0c2e6e29fc3a70a85",
    tarFlag: "-xjf",
  },
  libmtp: {
    version: "1.1.22",
    archive: "libmtp-1.1.22.tar.gz",
    url: "https://github.com/libmtp/libmtp/releases/download/v1.1.22/libmtp-1.1.22.tar.gz",
    sha256: "c3fcf411aea9cb9643590cbc9df99fa5fe30adcac695024442973d76fa5f87bc",
    tarFlag: "-xzf",
  },
} as const;

export type GarminFile = {
  id: number;
  name: string;
  size: number;
  type: number;
};

export type GarminState = {
  connected: boolean;
  manufacturer?: string;
  model?: string;
  serial?: string;
  storage?: {
    id: number;
    description: string;
    capacity: number;
    free: number;
  };
  podcastsFolderId?: number;
  files?: GarminFile[];
  message?: string;
  error?: string;
};

const helperOverride = () => env.PODRUSH_GARMIN_MTP_HELPER?.trim() || "";

const runProcess = async (
  command: string[],
  timeoutMs = 60_000,
  options: { cwd?: string; env?: Record<string, string> } = {}
) => {
  const proc = Bun.spawn(command, {
    cwd: options.cwd,
    env: options.env ? { ...process.env, ...options.env } : undefined,
    stdout: "pipe",
    stderr: "pipe",
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`Command timed out after ${Math.round(timeoutMs / 1000)} seconds`));
    }, timeoutMs);
  });

  try {
    const [exitCode, stdout, stderr] = await Promise.race([
      Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]),
      timeout,
    ]);
    return { exitCode, stdout, stderr };
  } finally {
    if (timer) clearTimeout(timer);
  }
};

const runBuildStep = async (
  command: string[],
  cwd?: string,
  extraEnv?: Record<string, string>
) => {
  const result = await runProcess(command, BUILD_TIMEOUT_MS, {
    cwd,
    env: extraEnv,
  });
  if (result.exitCode !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim();
    throw new Error(
      `Could not prepare direct Garmin support (${command[0]}): ${detail}`
    );
  }
};

const sha256 = async (path: string) => {
  const bytes = await Bun.file(path).arrayBuffer();
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
};

const ensureArchive = async (
  dependency: (typeof DEPENDENCIES)[keyof typeof DEPENDENCIES]
) => {
  mkdirSync(DOWNLOAD_DIR, { recursive: true });
  const destination = join(DOWNLOAD_DIR, dependency.archive);
  if (
    existsSync(destination) &&
    (await sha256(destination)) === dependency.sha256
  ) {
    return destination;
  }

  rmSync(destination, { force: true });
  let response: Response;
  try {
    response = await fetch(dependency.url);
  } catch (error) {
    throw new Error(
      `Could not download ${dependency.archive}. Check the internet connection and try again: ${error}`
    );
  }
  if (!response.ok) {
    throw new Error(
      `Could not download ${dependency.archive}: HTTP ${response.status}`
    );
  }
  await Bun.write(destination, await response.arrayBuffer());
  const digest = await sha256(destination);
  if (digest !== dependency.sha256) {
    rmSync(destination, { force: true });
    throw new Error(
      `Downloaded ${dependency.archive} failed its SHA-256 integrity check.`
    );
  }
  return destination;
};

const currentBuild = () => ({
  revision: BUILD_REVISION,
  architecture: process.arch,
  libusb: DEPENDENCIES.libusb.version,
  libmtp: DEPENDENCIES.libmtp.version,
  helperSourceMtimeMs: statSync(HELPER_SOURCE).mtimeMs,
});

const buildIsCurrent = () => {
  if (
    !existsSync(MARKER_PATH) ||
    !existsSync(HELPER_PATH) ||
    !existsSync(join(RUNTIME_DIR, "lib", "libmtp.9.dylib")) ||
    !existsSync(join(RUNTIME_DIR, "lib", "libusb-1.0.0.dylib"))
  ) {
    return false;
  }
  try {
    return (
      JSON.stringify(JSON.parse(readFileSync(MARKER_PATH, "utf8"))) ===
      JSON.stringify(currentBuild())
    );
  } catch {
    return false;
  }
};

const buildOpenSourceHelper = async () => {
  const [libusbArchive, libmtpArchive] = await Promise.all([
    ensureArchive(DEPENDENCIES.libusb),
    ensureArchive(DEPENDENCIES.libmtp),
  ]);

  rmSync(SOURCE_DIR, { recursive: true, force: true });
  rmSync(RUNTIME_DIR, { recursive: true, force: true });
  rmSync(HELPER_PATH, { force: true });
  rmSync(MARKER_PATH, { force: true });
  mkdirSync(SOURCE_DIR, { recursive: true });
  mkdirSync(RUNTIME_DIR, { recursive: true });

  const libusbSource = join(SOURCE_DIR, "libusb");
  const libmtpSource = join(SOURCE_DIR, "libmtp");
  mkdirSync(libusbSource, { recursive: true });
  mkdirSync(libmtpSource, { recursive: true });
  await runBuildStep([
    "tar",
    DEPENDENCIES.libusb.tarFlag,
    libusbArchive,
    "-C",
    libusbSource,
    "--strip-components=1",
  ]);
  await runBuildStep([
    "tar",
    DEPENDENCIES.libmtp.tarFlag,
    libmtpArchive,
    "-C",
    libmtpSource,
    "--strip-components=1",
  ]);

  const jobs = String(Math.max(1, Math.min(8, navigator.hardwareConcurrency || 4)));
  const configureCache = { lt_cv_sys_max_cmd_len: "262144" };
  await runBuildStep(
    [
      "./configure",
      `--prefix=${RUNTIME_DIR}`,
      "--disable-static",
      "--enable-shared",
    ],
    libusbSource,
    configureCache
  );
  await runBuildStep(["make", "-C", "libusb", `-j${jobs}`], libusbSource);
  await runBuildStep(["make", "-C", "libusb", "install"], libusbSource);

  await runBuildStep(
    [
      "./configure",
      `--prefix=${RUNTIME_DIR}`,
      "--disable-static",
      "--enable-shared",
      "--disable-mtpz",
    ],
    libmtpSource,
    {
      ...configureCache,
      PKG_CONFIG: "false",
      LIBUSB_CFLAGS: `-I${join(RUNTIME_DIR, "include", "libusb-1.0")}`,
      LIBUSB_LIBS: `-L${join(RUNTIME_DIR, "lib")} -lusb-1.0`,
    }
  );
  await runBuildStep(["make", "-C", "src", `-j${jobs}`], libmtpSource);
  await runBuildStep(["make", "-C", "src", "install"], libmtpSource);

  const libusbPath = join(RUNTIME_DIR, "lib", "libusb-1.0.0.dylib");
  const libmtpPath = join(RUNTIME_DIR, "lib", "libmtp.9.dylib");
  await runBuildStep([
    "install_name_tool",
    "-id",
    "@rpath/libusb-1.0.0.dylib",
    libusbPath,
  ]);
  await runBuildStep([
    "install_name_tool",
    "-id",
    "@rpath/libmtp.9.dylib",
    "-change",
    libusbPath,
    "@loader_path/libusb-1.0.0.dylib",
    libmtpPath,
  ]);
  await runBuildStep([
    "clang",
    HELPER_SOURCE,
    "-I",
    join(RUNTIME_DIR, "include"),
    "-L",
    join(RUNTIME_DIR, "lib"),
    "-lmtp",
    "-Wl,-rpath,@executable_path/runtime/lib",
    "-o",
    HELPER_PATH,
  ]);
  chmodSync(HELPER_PATH, 0o755);

  const licenseDir = join(RUNTIME_DIR, "licenses");
  mkdirSync(licenseDir, { recursive: true });
  copyFileSync(join(libusbSource, "COPYING"), join(licenseDir, "libusb-COPYING"));
  copyFileSync(join(libmtpSource, "COPYING"), join(licenseDir, "libmtp-COPYING"));
  writeFileSync(MARKER_PATH, `${JSON.stringify(currentBuild(), null, 2)}\n`);
};

const ensureBundledHelper = async (): Promise<string> => {
  const override = helperOverride();
  if (override) {
    if (!existsSync(override)) {
      throw new Error(`PODRUSH_GARMIN_MTP_HELPER does not exist: ${override}`);
    }
    return override;
  }

  if (process.platform !== "darwin") {
    throw new Error("Direct Garmin transfer is currently supported on macOS.");
  }
  if (!existsSync(HELPER_SOURCE)) {
    throw new Error(`Garmin helper source is missing: ${HELPER_SOURCE}`);
  }

  mkdirSync(TOOL_DIR, { recursive: true });
  if (!buildIsCurrent()) {
    log("Preparing native direct Garmin support", {
      architecture: process.arch,
      libusb: DEPENDENCIES.libusb.version,
      libmtp: DEPENDENCIES.libmtp.version,
    });
    await buildOpenSourceHelper();
  }
  return HELPER_PATH;
};

let garminJob: Promise<GarminState> | null = null;

const executeGarmin = async (
  command: "scan" | "send" | "delete",
  args: string[] = []
): Promise<GarminState> => {
  const helper = await ensureBundledHelper();
  const result = await runProcess([helper, command, ...args], USB_TIMEOUT_MS);
  const output = result.stdout.trim();
  const outputLines = output.split(/\r?\n/);
  const jsonLine = outputLines.findLast((line) => line.trimStart().startsWith("{")) || "";
  const stdoutDiagnostics = outputLines
    .filter((line) => line !== jsonLine)
    .join("\n")
    .trim();

  let state: GarminState;
  try {
    state = JSON.parse(jsonLine) as GarminState;
  } catch {
    const detail = result.stderr.trim() || output || `helper exited ${result.exitCode}`;
    throw new Error(`Garmin MTP helper returned invalid data: ${detail}`);
  }

  if (result.stderr.trim() || stdoutDiagnostics) {
    log("Garmin MTP diagnostics", {
      command,
      stderr: result.stderr.trim() || undefined,
      stdout: stdoutDiagnostics || undefined,
    });
  }
  if (result.exitCode !== 0 && !state.error) {
    state.error = `Garmin ${command} failed. Reconnect the watch and try again.`;
  }
  return state;
};

const queueGarmin = (
  command: "scan" | "send" | "delete",
  args: string[] = []
): Promise<GarminState> => {
  if (garminJob) {
    return Promise.resolve({
      connected: false,
      error: "Another Garmin operation is still running.",
    });
  }
  garminJob = executeGarmin(command, args).finally(() => {
    garminJob = null;
  });
  return garminJob;
};

export const scanGarmin = () => queueGarmin("scan");

export const sendConvertedToGarmin = (
  filenames: string[],
  entries: ConvertedEntry[]
) => {
  const byName = new Map(entries.map((entry) => [entry.filename, entry]));
  const paths = [...new Set(filenames)].map((filename) => {
    if (basename(filename) !== filename || !filename.toLowerCase().endsWith(".mp3")) {
      throw new Error(`Invalid converted filename: ${filename}`);
    }
    const entry = byName.get(filename);
    if (!entry) throw new Error(`Converted file not found: ${filename}`);
    return resolve(CONVERTED_DIR, entry.filename);
  });
  if (!paths.length) throw new Error("Select at least one converted MP3.");
  return queueGarmin("send", paths);
};

export const deleteGarminFiles = (ids: number[]) => {
  const safeIds = [...new Set(ids)].filter(
    (id) => Number.isInteger(id) && id > 0 && id <= 0xffffffff
  );
  if (!safeIds.length) throw new Error("Select at least one watch file.");
  return queueGarmin("delete", safeIds.map(String));
};
