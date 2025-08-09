-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "uploadedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "yaraMatches" TEXT,
    "regexMatches" TEXT,
    "mlScore" DOUBLE PRECISION,
    "riskLevel" TEXT NOT NULL,
    "reportUrl" TEXT,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);
