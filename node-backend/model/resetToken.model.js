"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mongoose_1 = require("mongoose");
const generateOtp_1 = require("../util/generateOtp");
const generateResetToken_1 = require("../util/generateResetToken");
const ResetTokenSchema = new mongoose_1.Schema({
    email: { type: String, required: true, unique: true },
    token: { type: String, default: '' },
    otp: { type: String, default: '' },
});
ResetTokenSchema.pre('save', function (next) {
    if (!this.otp) {
        this.otp = (0, generateOtp_1.generateOtp)();
        this.token = (0, generateResetToken_1.generateResetToken)();
    }
    next();
});
const ResetTokenModel = (0, mongoose_1.model)('ResetToken', ResetTokenSchema);
exports.default = ResetTokenModel;
