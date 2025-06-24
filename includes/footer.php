</main>
    
    <!-- Footer -->
    <footer class="bg-light py-3 mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p class="mb-0 text-muted">
                        &copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?> v<?php echo APP_VERSION; ?>
                    </p>
                </div>
                <div class="col-md-6 text-end">
                    <small class="text-muted">
                        Last updated: <?php echo date('Y-m-d H:i:s'); ?>
                    </small>
                </div>
            </div>
        </div>
    </footer>
    
    <!-- Page-specific JavaScript -->
    <?php if (isset($page_js)): ?>
        <script><?php echo $page_js; ?></script>
    <?php endif; ?>
</body>
</html>