export const WINDOWS_FS_SAFE_NATIVE_DIR: string;
export const WINDOWS_FS_SAFE_BINDING_OUTPUT: string;
export const WINDOWS_FS_SAFE_LICENSE_OUTPUT: string;
export function writeTextFileIfChanged(filePath: string, contents: unknown): boolean;
export function removeFileIfExists(filePath: string): boolean;
export function removePathIfExists(filePath: string): boolean;
