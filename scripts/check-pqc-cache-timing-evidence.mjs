#!/usr/bin/env node

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const threshold = 4.5;
const reportRoot = join(process.cwd(), "docs", "security", "ct-reports");
const expectedEvents = ["D1mr", "D1mw", "DLmr", "DLmw", "Dr", "Dw", "I1mr", "ILmr", "Ir"];
const expectedSuites = [
  "aes_gcm_unwrap",
  "aes_gcm_wrap",
  "ml_dsa44_sign",
  "ml_dsa44_verify",
  "ml_dsa65_sign",
  "ml_dsa65_verify",
  "ml_dsa87_sign",
  "ml_dsa87_verify",
  "ml_kem1024_decap",
  "ml_kem1024_encap",
  "ml_kem512_decap",
  "ml_kem512_encap",
  "ml_kem768_decap",
  "ml_kem768_encap",
];

const actualSuites = readdirSync(reportRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

if (JSON.stringify(actualSuites) !== JSON.stringify(expectedSuites)) {
  throw new Error(
    `timing evidence inventory mismatch\nexpected: ${expectedSuites.join(", ")}\nactual: ${actualSuites.join(", ")}`,
  );
}

let highestAbsoluteT = 0;
let highestEvent = "";

for (const suite of expectedSuites) {
  const reportPath = join(reportRoot, suite, "report.json");
  const report = JSON.parse(readFileSync(reportPath, "utf8"));
  const eventNames = Object.keys(report.events ?? {}).sort();
  const events = Object.entries(report.events ?? {});

  if (report.threshold !== threshold) {
    throw new Error(`${suite}: expected threshold ${threshold}, got ${report.threshold}`);
  }
  if (report.overall?.leak !== false) {
    throw new Error(`${suite}: overall.leak must be false`);
  }
  if (report.kPerClass?.cls0 !== 20 || report.kPerClass?.cls1 !== 20) {
    throw new Error(`${suite}: expected 20 samples in each class`);
  }
  if (JSON.stringify(eventNames) !== JSON.stringify(expectedEvents)) {
    throw new Error(`${suite}: cache event inventory mismatch: ${eventNames.join(", ")}`);
  }

  for (const [event, result] of events) {
    if (result.leak !== false || !Number.isFinite(result.t)) {
      throw new Error(`${suite}/${event}: invalid non-leak result`);
    }
    const absoluteT = Math.abs(result.t);
    if (absoluteT >= threshold) {
      throw new Error(`${suite}/${event}: |t|=${absoluteT} exceeds threshold ${threshold}`);
    }
    if (absoluteT > highestAbsoluteT) {
      highestAbsoluteT = absoluteT;
      highestEvent = `${suite}/${event}`;
    }
  }
}

console.log(
  `validated ${expectedSuites.length} cache-timing evidence reports; ` +
    `highest |t|=${highestAbsoluteT.toFixed(3)} at ${highestEvent}`,
);
