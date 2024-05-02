-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "key" TEXT NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Credential" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "publicKey" TEXT NOT NULL,
    "counter" INTEGER NOT NULL,
    "transports" TEXT,

    CONSTRAINT "Credential_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_key_key" ON "User"("key");

-- AddForeignKey
ALTER TABLE "Credential" ADD CONSTRAINT "Credential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
