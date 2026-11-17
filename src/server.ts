
import 'dotenv/config';

import app from './app.js';
import redisClient from './config/redis.js';
import { pool } from './database/index.js';

const PORT = Number(process.env.PORT) || 3000;

const startServer = async (): Promise<void> => {
    // Handling Gracefull Shutdown
    let httpServer: ReturnType<typeof app.listen> | undefined;
    let isShuttingDown = false;

    const shutdown = async (signal: string) => {
        if (isShuttingDown) return;

        isShuttingDown = true;

        console.log(`Received ${signal}. Shutting down...`);

        try {
            // Stop Accepting new HTTP connections
            if (httpServer)
            {
                await new Promise<void>((resolve, reject) => {
                    httpServer!.close((error) => {
                        if (error) reject(error);
                        else resolve();
                    });
                });
            }

            // Close Database and Redis Connections
            const results = await Promise.allSettled([
                pool.end(),
                redisClient.isOpen
                    ? redisClient.quit()
                    : Promise.resolve(),
            ]);

            for (const result of results)
            {
                if (result.status === 'rejected')
                {
                    console.error('Resource cleanup failed:', result.reason);
                    process.exitCode = 1;
                }
            }

            console.log("Application Shutdown completed.");
            process.exit(0);
        } catch (error) {
            console.error("Shutdown failed: ", error);
            process.exitCode = 1;
        }
    };

  try {
    // Connect Redis
    if (!redisClient.isOpen) {
      await redisClient.connect();
      console.log('Redis Connected');
    }

    // Verify PostgreSQL connection
    await pool.query('SELECT 1');
    console.log('PostgreSQL Connected');

    // Start HTTP server
    httpServer = app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });

    // Handle graceful shutdown
    process.on('SIGINT', () => {
      void shutdown('SIGINT');
    });

    process.on('SIGTERM', () => {
      void shutdown('SIGTERM');
    });

  } catch (error) {
    console.error('Server startup failed:', error);

    await pool.end().catch(() => undefined);

    if (redisClient.isOpen) {
      await redisClient.quit().catch(() => undefined);
    }

    process.exit(1);
  }
};

startServer();
