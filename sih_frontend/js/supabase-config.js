import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm'

export const supabase = createClient(
  'https://sarmwmdqgkappmekzlmp.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNhcm13bWRxZ2thcHBtZWt6bG1wIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODgyNjI4MjksImV4cCI6MjEwMzgzODgyOX0.u6Jxwy2kGs34hBQM_gX8_Wb9YH78nx7KFP9K_Mumh7A'
)