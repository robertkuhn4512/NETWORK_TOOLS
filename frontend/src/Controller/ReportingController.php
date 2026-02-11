<?php

namespace App\Controller;

use App\Service\FastApi\FastApiClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class ReportingController extends AbstractController
{
    #[Route('/api/reporting/devices', name: 'api_reporting_devices_initial', methods: ['GET'])]
    public function devicesInitial(Request $request, FastApiClient $fastApi): JsonResponse
    {
        // limit comes from the URL: /api/reporting/devices?limit=500
        $limitRaw = $request->query->get('limit', 10);
        $limit = is_numeric($limitRaw) ? (int)$limitRaw : 10;

        // default to 10 if missing/invalid
        if ($limit <= 0) {
            $limit = 500;
        }

        // optional safety clamp (avoid someone requesting 1M rows)
        $limit = min($limit, 5000);

        $res = $fastApi->fetchDevicesDatatableInitial($limit);

        return new JsonResponse(
            $res['data'],
            $res['status'] ?? 500
        );
    }
}
