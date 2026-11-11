"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setNewPassword = exports.forgotPassword = void 0;
const user_model_1 = __importDefault(require("../model/user.model"));
const resetToken_model_1 = __importDefault(require("../model/resetToken.model"));
const forgotPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email } = req.body;
    try {
        const user = yield user_model_1.default.findOne({ email });
        if (user) {
            yield resetToken_model_1.default.deleteMany({ email }).then(() => console.log("deleted"));
            const resetToken = yield resetToken_model_1.default.create({ email });
            console.log(resetToken);
            return res.status(200).json({ token: resetToken.token });
        }
        return res.status(404).json({ error: 'User not found' });
    }
    catch (error) {
        return res.status(500).json({ error });
    }
});
exports.forgotPassword = forgotPassword;
const setNewPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { password, token } = req.body;
        const resetToken = yield resetToken_model_1.default.findOne({ token });
        if (resetToken) {
            const user = yield user_model_1.default.findOne({ email: resetToken.email });
            if (user) {
                user.password = password;
                yield user.save();
                yield resetToken_model_1.default.deleteMany({ email: resetToken.email });
                return res.status(200).json({ user });
            }
        }
    }
    catch (error) {
        return res.status(500).json({ error });
    }
});
exports.setNewPassword = setNewPassword;
