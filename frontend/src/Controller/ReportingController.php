<?php

namespace App\Controller;

use App\Service\FastApi\FastApiClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class ReportingController extends AbstractController
{
    #[Route('/api/reporting/devices', name: 'api_reporting_devices_initial', methods: ['GET', 'POST'])]
    public function devicesInitial(Request $request, FastApiClient $fastApi): JsonResponse
    {
        $rid = $request->headers->get('X-Request-ID') ?: bin2hex(random_bytes(8));

        // If DataTables is calling this endpoint, it will be POST JSON
        if ($request->isMethod('POST')) {
            $raw = (string) $request->getContent();
            $payload = json_decode($raw, true);

            if (!is_array($payload)) {
                $out = new JsonResponse([
                    'detail' => 'Invalid JSON payload (expected DataTables request object).',
                    'rid' => $rid,
                ], 400);
                $out->headers->set('X-Request-ID', $rid);
                return $out;
            }

            $res = $fastApi->fetchDevicesDatatable($payload, $rid);

            if (!($res['ok'] ?? false)) {
                $status = (int)($res['status'] ?? 502);
                $out = new JsonResponse([
                    'detail' => $res['error']['message'] ?? 'FastAPI request failed.',
                    'error' => $res['error'] ?? null,
                    'rid' => $rid,
                ], $status);
                $out->headers->set('X-Request-ID', $rid);
                return $out;
            }

            $data = $res['data'];
            if (is_array($data) && isset($data['detail']) && is_array($data['detail'])) {
                $data = $data['detail'];
            }

            $out = new JsonResponse($data, (int)($res['status'] ?? 200));
            $out->headers->set('X-Request-ID', $rid);
            return $out;
        }

        // Fallback GET: build a minimal DT payload using `limit` for initial testing
        $limitRaw = $request->query->get('limit', 25);
        $limit = is_numeric($limitRaw) ? (int) $limitRaw : 25;
        $limit = max(1, min($limit, 5000));

        $payload = [
            'draw' => 1,
            'start' => 0,
            'length' => $limit,
            'search' => ['value' => '', 'regex' => false],
            'order' => [['column' => 0, 'dir' => 'asc']],
            // NOTE: columns will be filled by DataTables on real POST requests;
            // for GET fallback, you can omit or keep empty.
            'columns' => [],
        ];

        $res = $fastApi->fetchDevicesDatatable($payload, $rid);

        if (!($res['ok'] ?? false)) {
            $status = (int)($res['status'] ?? 502);
            $out = new JsonResponse([
                'detail' => $res['error']['message'] ?? 'FastAPI request failed.',
                'error' => $res['error'] ?? null,
                'rid' => $rid,
            ], $status);
            $out->headers->set('X-Request-ID', $rid);
            return $out;
        }

        $data = $res['data'];
        if (is_array($data) && isset($data['detail']) && is_array($data['detail'])) {
            $data = $data['detail'];
        }

        $out = new JsonResponse($data, (int)($res['status'] ?? 200));
        $out->headers->set('X-Request-ID', $rid);
        return $out;
    }

    /*
     * This endpoint is used to query device information in the datatables format.
     * The related fastapi endpoint is below
     * /device_reporting/datatable/devices
     *
     */
    #[Route('/api/reporting/devices/datatable', name: 'api_reporting_devices_datatable', methods: ['GET'])]
    public function devicesDatatable(Request $request, FastApiClient $fastApi): JsonResponse
    {
        $rid = $request->headers->get('X-Request-ID') ?: bin2hex(random_bytes(8));

        $draw = (int) $request->query->get('draw', 1);
        $start = max(0, (int) $request->query->get('start', 0));
        $length = min(250, max(1, (int) $request->query->get('length', 25)));

        $searchValue = (string) ($request->query->all('search')['value'] ?? '');

        $order = $request->query->all('order');
        $columns = $request->query->all('columns');

        $orderColIdx = isset($order[0]['column']) ? (int)$order[0]['column'] : 0;
        $orderDir = isset($order[0]['dir']) ? (string)$order[0]['dir'] : 'asc';
        $orderDir = strtolower($orderDir) === 'desc' ? 'desc' : 'asc';

        $orderField = $columns[$orderColIdx]['data'] ?? 'device_name';

        $res = $fastApi->fetchDevicesDatatableServerSide(
            start: $start,
            length: $length,
            search: $searchValue,
            orderField: $orderField,
            orderDir: $orderDir,
            rid: $rid
        );

        if (!($res['ok'] ?? false)) {
            $out = new JsonResponse(['detail' => 'FastAPI request failed.', 'rid' => $rid, 'error' => $res['error'] ?? null], (int)($res['status'] ?? 502));
            $out->headers->set('X-Request-ID', $rid);
            return $out;
        }

        $data = $res['data'] ?? [];
        // Ensure top-level keys, not wrapped
        if (isset($data['detail']) && is_array($data['detail'])) $data = $data['detail'];

        $data['draw'] = $draw;

        $out = new JsonResponse($data, 200);
        $out->headers->set('X-Request-ID', $rid);
        return $out;
    }

    /*
     * This endpoint is used to generate a devices datatable
     */
    #[Route('/reporting/table/devices', name: 'reporting_table_devices', methods: ['GET'])]
    public function devicesTable(Request $request): Response
    {
        $rid = bin2hex(random_bytes(8));

        $table = [
            'rid' => $rid,

            'title' => 'Devices',
            'id' => 'dt_devices',

            // Keep as server-side (your FastAPI should return draw/recordsTotal/recordsFiltered/data)
            'serverSide' => true,
            'processing' => true,

            'ajax' => [
                'url' => $this->generateUrl('api_reporting_devices_initial'),
                'method' => 'POST',
                'send_json' => true,

                // DataTables parameters (draw/start/length/search/order/columns) are required
                'send_dt_params' => true,

                // remove param_map; FastAPI expects start/length already
                'param_map' => [],

                'payload' => [
                    // optional: add any static filters here
                ],

                // keep 'data' if controller unwraps
                'dataSrc' => 'data',

                'headers' => [
                    'X-Request-ID' => $rid,
                ],
            ],

            'columns' => [
                ['data' => 'device_name',      'label' => 'Device Name',      'orderable' => true,  'searchable' => true],
                ['data' => 'ipv4_loopback',    'label' => 'IPv4 Loopback',    'orderable' => true,  'searchable' => true],
                ['data' => 'os',               'label' => 'OS',               'orderable' => true,  'searchable' => true],
                ['data' => 'device_type',      'label' => 'Device Type',      'orderable' => true,  'searchable' => true],
                ['data' => 'version',          'label' => 'Software Version', 'orderable' => true,  'searchable' => true],
                ['data' => 'chassis_model',    'label' => 'Chassis Model',    'orderable' => true,  'searchable' => true],
                ['data' => 'datetimestamp',    'label' => 'Last Discovered',  'orderable' => true,  'searchable' => false],

                // OPTIONAL: “Information” modal column
                [
                    'data' => 'information',
                    'label' => 'Information',
                    'orderable' => false,
                    'searchable' => false,

                    // modal support
                    'modal' => true,
                    'modal_data' => 'information',          // can also be ['field1','field2'] or ['Label'=>'field']
                    'modal_title' => 'Device Information',  // optional
                    'modal_button_text' => 'View',          // optional
                    'className' => 'text-center align-middle',
                ],
            ],

            'order' => [
                [0, 'asc'],
            ],

            'pageLength' => 25,
            'lengthMenu' => [10, 25, 50, 100, 250],

            'features' => [
                'paging' => true,
                'searching' => true,
                'ordering' => true,
                'info' => true,
                'responsive' => true,
                'select' => true,
                'buttons' => true,
            ],

            'buttons' => ['copy', 'csv', 'excel', 'print', 'colvis'],

            'editor' => [
                'enabled' => false,
            ],

            'debug' => (bool) $this->getParameter('kernel.debug'),
        ];

        return $this->render('reporting/universal_datatable.html.twig', [
            'table' => $table,
        ]);
    }
}
