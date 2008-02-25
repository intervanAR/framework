
------------------------------------------------------------
-- apex_proyecto
------------------------------------------------------------
INSERT INTO apex_proyecto (proyecto, descripcion, descripcion_corta, estilo, con_frames, frames_clase, frames_archivo, salida_impr_html_c, salida_impr_html_a, menu, path_includes, path_browser, administrador, listar_multiproyecto, orden, palabra_vinculo_std, version_toba, requiere_validacion, usuario_anonimo, usuario_anonimo_desc, usuario_anonimo_grupos_acc, validacion_intentos, validacion_intentos_min, validacion_bloquear_usuario, validacion_debug, sesion_tiempo_no_interac_min, sesion_tiempo_maximo_min, sesion_subclase, sesion_subclase_archivo, contexto_ejecucion_subclase, contexto_ejecucion_subclase_archivo, usuario_subclase, usuario_subclase_archivo, encriptar_qs, registrar_solicitud, registrar_cronometro, item_inicio_sesion, item_pre_sesion, item_set_sesion, log_archivo, log_archivo_nivel, fuente_datos, pagina_tipo, version, version_fecha, version_detalle, version_link) VALUES (
	'toba_usuarios', --proyecto
	'TOBA_USUARIOS', --descripcion
	'Toba_usuarios', --descripcion_corta
	'plastik', --estilo
	'1', --con_frames
	NULL, --frames_clase
	NULL, --frames_archivo
	NULL, --salida_impr_html_c
	NULL, --salida_impr_html_a
	'css', --menu
	NULL, --path_includes
	NULL, --path_browser
	NULL, --administrador
	'1', --listar_multiproyecto
	NULL, --orden
	NULL, --palabra_vinculo_std
	'1.2.0alpha', --version_toba
	'1', --requiere_validacion
	NULL, --usuario_anonimo
	NULL, --usuario_anonimo_desc
	NULL, --usuario_anonimo_grupos_acc
	NULL, --validacion_intentos
	NULL, --validacion_intentos_min
	'1', --validacion_bloquear_usuario
	'0', --validacion_debug
	NULL, --sesion_tiempo_no_interac_min
	NULL, --sesion_tiempo_maximo_min
	'sesion', --sesion_subclase
	'customizacion_toba/sesion.php', --sesion_subclase_archivo
	'contexto_ejecucion', --contexto_ejecucion_subclase
	'customizacion_toba/contexto_ejecucion.php', --contexto_ejecucion_subclase_archivo
	NULL, --usuario_subclase
	NULL, --usuario_subclase_archivo
	'0', --encriptar_qs
	'0', --registrar_solicitud
	NULL, --registrar_cronometro
	'/inicio', --item_inicio_sesion
	'3422', --item_pre_sesion
	'3428', --item_set_sesion
	'1', --log_archivo
	'7', --log_archivo_nivel
	'toba_usuarios', --fuente_datos
	NULL, --pagina_tipo
	NULL, --version
	NULL, --version_fecha
	NULL, --version_detalle
	NULL  --version_link
);
