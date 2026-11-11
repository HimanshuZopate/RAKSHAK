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
const mongoose_1 = require("mongoose");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const UserSchema = new mongoose_1.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            'Please provide a valid email address',
        ],
    },
    displayName: {
        type: String,
        trim: true,
        maxlength: 80,
        default: '',
    },
    avatarUrl: {
        type: String,
        trim: true,
        maxlength: 500,
        default: '',
    },
    password: {
        type: String,
        minlength: [8, 'Password must be at least 8 characters long'],
        required: true,
    },
    isEmailVerified: {
        type: Boolean,
        default: false,
    },
    verificationToken: {
        type: String,
        default: null,
        select: false, // Hidden from queries by default for defense in depth
    },
    verificationTokenExpires: {
        type: Date,
        default: null,
        select: false,
    },
    refreshToken: {
        type: String,
        default: null,
        select: false, // Hidden from general queries
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
}, {
    timestamps: true,
});
// Pre-save hook: Hash password with bcrypt (12 rounds) when modified
UserSchema.pre('save', function (next) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!this.isModified('password') || !this.password) {
            return next();
        }
        try {
            const salt = yield bcryptjs_1.default.genSalt(12);
            this.password = yield bcryptjs_1.default.hash(this.password, salt);
            next();
        }
        catch (err) {
            next(err);
        }
    });
});
// Compare candidate password with stored hash
UserSchema.methods.comparePassword = function (candidatePassword) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!this.password) {
            return false;
        }
        return bcryptjs_1.default.compare(candidatePassword, this.password);
    });
};
// Safe DTO serialization avoiding leaking sensitive tokens/hashes
UserSchema.methods.toSafeUser = function () {
    return {
        id: this._id.toString(),
        email: this.email,
        displayName: this.displayName,
        avatarUrl: this.avatarUrl,
        isEmailVerified: this.isEmailVerified,
        role: this.role,
        createdAt: this.createdAt,
    };
};
const UserModel = (0, mongoose_1.model)('User', UserSchema);
exports.default = UserModel;
