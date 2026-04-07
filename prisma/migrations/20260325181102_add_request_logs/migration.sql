/*
  Warnings:

  - The primary key for the `IpBlock` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `id` on the `IpBlock` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "IpBlock_ip_key";

-- AlterTable
ALTER TABLE "IpBlock" DROP CONSTRAINT "IpBlock_pkey",
DROP COLUMN "id",
ADD CONSTRAINT "IpBlock_pkey" PRIMARY KEY ("ip");

-- CreateTable
CREATE TABLE "RequestLog" (
    "id" SERIAL NOT NULL,
    "ip" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "headerSize" INTEGER NOT NULL,
    "responseTime" INTEGER NOT NULL,

    CONSTRAINT "RequestLog_pkey" PRIMARY KEY ("id")
);
