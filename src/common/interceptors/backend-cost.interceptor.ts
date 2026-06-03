import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { performance } from 'perf_hooks';
import { createHash } from 'crypto';
import { requestContext } from '../request-context/request-context';

@Injectable()
export class BackendCostInterceptor implements NestInterceptor {
  // İsteğin (request) NestJS kontrolcüsüne (controller) girip işleme başladığı tam o saniyeyi kaydeden ve işi bittiğinde başlık yazma sürecini başlatan kronometre hakemidir.
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> { 
    const httpCtx = ctx.switchToHttp();
    const req = httpCtx.getRequest();
    const res = httpCtx.getResponse();

    // tHandlerStart'ı kaydet (request context middleware'da kuruldu)
    const store = requestContext.getStore();
    if (store) {
      store.tHandlerStart = performance.now();
    }

    return next.handle().pipe(
      tap({
        next: () => this.writeHeaders(req, res, store),
        error: () => this.writeHeaders(req, res, store),
      }),
    );
  }

  // İçeride (AsyncLocalStorage kasasında) toplanan tüm CPU, veritabanı ve gizlilik metriklerini alıp, istemciye geri dönecek olan HTTP paketinin kafasına birer etiket (Header) olarak tek tek yapıştıran fabrika işçisidir.
  private writeHeaders(req: any, res: any, store: any) {
    if (!store) return;
    if (res.headersSent) return;

    store.tHandlerEnd = performance.now();
    const cpuDiff = process.cpuUsage(store.cpuStart);
    const cpuTimeMs = (cpuDiff.user + cpuDiff.system) / 1000;

    const routeTemplate = req.route?.path || req.url?.split('?')[0] || 'unknown';

    const userId = req.user?.userId;
    const sessionIdHash = userId
      ? createHash('sha256').update(String(userId)).digest('hex').slice(0, 32)
      : '';
    const loginPresent = userId ? '1' : '0';

    res.setHeader('X-Route-Template', routeTemplate);
    res.setHeader('X-DB-Query-Count', String(store.dbQueryCount));
    res.setHeader('X-DB-Total-Time-Ms', store.dbTotalTimeMs.toFixed(2));
    res.setHeader('X-CPU-Time-Ms', cpuTimeMs.toFixed(2));
    res.setHeader('X-External-Call-Count', String(store.externalCallCount));
    res.setHeader('X-Session-Id-Hash', sessionIdHash);
    res.setHeader('X-Login-Present', loginPresent);
    res.setHeader('X-T-Recv', String(store.tRecv));
    res.setHeader('X-T-Handler-Start', store.tHandlerStart.toFixed(3));
    res.setHeader('X-T-Handler-End', store.tHandlerEnd.toFixed(3));
  }
}