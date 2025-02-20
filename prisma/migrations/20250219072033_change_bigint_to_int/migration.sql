-- CreateTable
CREATE TABLE "account" (
    "id" SERIAL NOT NULL,
    "username" VARCHAR(50),
    "password" VARCHAR(16),
    "active" BOOLEAN DEFAULT false,
    "wrong_attempt" SMALLINT DEFAULT 0,
    "wrong_otp_attempt" SMALLINT DEFAULT 0,
    "last_login" INTEGER,
    "status" INTEGER,
    "locked" BOOLEAN DEFAULT false,
    "is_deleted" BOOLEAN DEFAULT false,
    "mpin" INTEGER,
    "device_type" VARCHAR(20),
    "device_id" VARCHAR(255),
    "created_ts" INTEGER DEFAULT EXTRACT(epoch FROM now()),
    "updated_ts" INTEGER,

    CONSTRAINT "pk_account" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "enrollment" (
    "id" SERIAL NOT NULL,
    "guid" VARCHAR(250),
    "start_date" INTEGER,
    "expiry_date" INTEGER,
    "account_id" INTEGER,
    "type" VARCHAR(50),
    "status" VARCHAR(10),
    "created_ts" INTEGER DEFAULT EXTRACT(epoch FROM now()),
    "updated_ts" INTEGER,

    CONSTRAINT "pk_enrollment" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "permission" (
    "id" SERIAL NOT NULL,
    "permission_name" VARCHAR(255),
    "description" TEXT,

    CONSTRAINT "pk_permission" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role" (
    "id" SERIAL NOT NULL,
    "name" VARCHAR(250),
    "code" VARCHAR(50),

    CONSTRAINT "pk_role" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_permission" (
    "id" SERIAL NOT NULL,
    "role_id" INTEGER,
    "permission_id" INTEGER,
    "created_ts" INTEGER DEFAULT EXTRACT(epoch FROM now()),
    "updated_ts" INTEGER,

    CONSTRAINT "pk_role_permission" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_role" (
    "id" SERIAL NOT NULL,
    "user_id" INTEGER,
    "role_id" INTEGER,
    "start_date" INTEGER,
    "end_date" INTEGER,
    "created_ts" INTEGER DEFAULT EXTRACT(epoch FROM now()),
    "updated_ts" INTEGER,

    CONSTRAINT "pk_user_role" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "first_name" VARCHAR(250),
    "last_name" VARCHAR(250),
    "phone" VARCHAR(12),
    "email" VARCHAR(50),
    "type" VARCHAR(10),
    "is_deleted" BOOLEAN DEFAULT false,
    "created_ts" INTEGER DEFAULT EXTRACT(epoch FROM now()),
    "updated_ts" INTEGER,
    "account_id" INTEGER,

    CONSTRAINT "pk_users" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "unique_username" ON "account"("username");

-- CreateIndex
CREATE UNIQUE INDEX "unique_email" ON "users"("email");

-- AddForeignKey
ALTER TABLE "enrollment" ADD CONSTRAINT "fk_enrollment_account" FOREIGN KEY ("account_id") REFERENCES "account"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "role_permission" ADD CONSTRAINT "fk_role_permission_permission" FOREIGN KEY ("permission_id") REFERENCES "permission"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "role_permission" ADD CONSTRAINT "fk_role_permission_role" FOREIGN KEY ("role_id") REFERENCES "role"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_role" ADD CONSTRAINT "fk_user_role_role" FOREIGN KEY ("role_id") REFERENCES "role"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "user_role" ADD CONSTRAINT "fk_user_role_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "fk_users_account" FOREIGN KEY ("account_id") REFERENCES "account"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
