"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateOtp = void 0;
function generateOtp() {
    const token = Math.floor(Math.random() * (9999 - 1000 + 1) + 1000);
    return token.toString();
}
exports.generateOtp = generateOtp;
