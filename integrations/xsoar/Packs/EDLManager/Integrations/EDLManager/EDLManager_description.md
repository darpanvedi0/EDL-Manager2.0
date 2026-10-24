## EDL Manager

1. In EDL Manager, go to **Admin > API Keys** and create a key for Cortex XSOAR. Give it the permissions for the commands you plan to use:
   - **view**: get and list requests, entries, and metrics
   - **submit**: `edl-manager-request-submit`
   - **approve**: `edl-manager-request-approve` and `edl-manager-request-deny`
   - **remove**: `edl-manager-entry-remove`
2. Enter the EDL Manager address as the **Server URL** and the key as the **API Key**.

If the EDL Manager web server doesn't route `/api/v1/*` to the API, set **API path** to `/api/v1/index.php`.