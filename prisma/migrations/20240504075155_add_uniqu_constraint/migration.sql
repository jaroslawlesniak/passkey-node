/*
  Warnings:

  - A unique constraint covering the columns `[token]` on the table `Credential` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "Credential_token_key" ON "Credential"("token");
