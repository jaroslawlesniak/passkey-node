/*
  Warnings:

  - The `transports` column on the `Credential` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- AlterTable
ALTER TABLE "Credential" DROP COLUMN "transports",
ADD COLUMN     "transports" TEXT[];
