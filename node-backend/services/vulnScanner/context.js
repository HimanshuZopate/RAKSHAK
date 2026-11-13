"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.COMPREHENSIVE_ONLY = exports.STANDARD_UP = exports.ALL_PROFILES = exports.skipped = exports.inconclusive = exports.result = void 0;
const result = (findings, note) => ({
    status: findings.some((f) => f.severity !== 'info') ? 'issues' : 'passed',
    findings,
    note,
});
exports.result = result;
const inconclusive = (note, findings = []) => ({ status: 'inconclusive', findings, note });
exports.inconclusive = inconclusive;
const skipped = (note) => ({ status: 'skipped', findings: [], note });
exports.skipped = skipped;
exports.ALL_PROFILES = ['quick', 'standard', 'comprehensive'];
exports.STANDARD_UP = ['standard', 'comprehensive'];
exports.COMPREHENSIVE_ONLY = ['comprehensive'];
