import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface IUser extends Document {
  email: string;
  displayName?: string;
  avatarUrl?: string;
  password?: string;
  isEmailVerified: boolean;
  verificationToken?: string | null;
  verificationTokenExpires?: Date | null;
  refreshToken?: string | null;
  role: 'user' | 'admin';
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
  toSafeUser(): {
    id: string;
    email: string;
    isEmailVerified: boolean;
    role: string;
    createdAt: Date;
  };
}

const UserSchema = new Schema<IUser>(
  {
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
  },
  {
    timestamps: true,
  }
);

// Pre-save hook: Hash password with bcrypt (12 rounds) when modified
UserSchema.pre<IUser>('save', async function (next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err: any) {
    next(err);
  }
});

// Compare candidate password with stored hash
UserSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  if (!this.password) {
    return false;
  }
  return bcrypt.compare(candidatePassword, this.password);
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

const UserModel = model<IUser>('User', UserSchema);

export default UserModel;
